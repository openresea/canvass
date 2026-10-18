"""Versioned deployment-wide survey; mutations require a global admin."""

import json
import uuid
from fastapi import HTTPException
from app.common.db import get_ops, put_ops
from app.common.util import fetchall_dict, fetchone_dict


def question_data(body):
    prompt, kind = body.get("prompt"), body.get("kind")
    required, options = body.get("required", False), body.get("options", [])
    if not isinstance(prompt, str) or not 1 <= len(prompt.strip()) <= 300:
        raise HTTPException(400, "Write a question between 1 and 300 characters.")
    if kind not in ("text", "single_choice", "yes_no") or type(required) is not bool:
        raise HTTPException(400, "Choose a valid answer type and required setting.")
    if kind == "single_choice":
        if not isinstance(options, list) or not 2 <= len(options) <= 12:
            raise HTTPException(400, "Provide 2–12 answer choices.")
        if any(
            not isinstance(v, str) or not 1 <= len(v.strip()) <= 120 for v in options
        ):
            raise HTTPException(400, "Each choice must contain 1–120 characters.")
        options = [v.strip() for v in options]
        if len(set(v.casefold() for v in options)) != len(options):
            raise HTTPException(400, "Answer choices must be different.")
    else:
        options = ["Yes", "No", "Not sure"] if kind == "yes_no" else []
    return dict(prompt=prompt.strip(), kind=kind, required=required, options=options)


def read_survey(cur, *, archived=False):
    # Shared lock prevents a snapshot mixing questions from different revisions.
    cur.execute("SELECT pg_advisory_xact_lock_shared(782124)")
    cur.execute("SELECT version FROM survey_state WHERE singleton=true")
    version = fetchone_dict(cur)["version"]
    cur.execute(
        """SELECT question_id::text AS id, prompt, kind, required, options, position, archived
                   FROM survey_questions WHERE (%s OR NOT archived)
                   ORDER BY archived, position, question_id""",
        (archived,),
    )
    return {"version": version, "questions": fetchall_dict(cur)}


def load_survey(*, archived=False):
    conn = get_ops()
    try:
        with conn, conn.cursor() as cur:
            return read_survey(cur, archived=archived)
    finally:
        put_ops(conn)


def change_survey(body, actor):
    version, action, qid = body.get("version"), body.get("action"), body.get("id")
    if type(version) is not int or action not in (
        "add",
        "edit",
        "archive",
        "restore",
        "move",
    ):
        raise HTTPException(400, "Invalid survey change.")
    if action != "add":
        try:
            qid = str(uuid.UUID(str(qid)))
        except ValueError:
            raise HTTPException(400, "Invalid question ID.")
    data = question_data(body) if action in ("add", "edit") else None
    conn = get_ops()
    try:
        with conn, conn.cursor() as cur:
            cur.execute("SELECT pg_advisory_xact_lock(782124)")
            cur.execute(
                "SELECT version FROM survey_state WHERE singleton=true FOR UPDATE"
            )
            if fetchone_dict(cur)["version"] != version:
                raise HTTPException(
                    409,
                    "Another admin changed the survey. Reload the questions before saving.",
                )
            current = read_survey(cur, archived=True)["questions"]
            active = [q for q in current if not q["archived"]]
            question = next((q for q in current if q["id"] == qid), None)
            if action != "add" and question is None:
                raise HTTPException(404, "Question not found.")
            if action in ("add", "restore") and len(active) >= 50:
                raise HTTPException(
                    400, "A survey can contain up to 50 active questions."
                )
            if action == "add":
                qid = str(uuid.uuid4())
                cur.execute(
                    """INSERT INTO survey_questions(question_id,prompt,kind,required,options,position)
                               VALUES (%s,%s,%s,%s,%s::jsonb,%s)""",
                    (
                        qid,
                        data["prompt"],
                        data["kind"],
                        data["required"],
                        json.dumps(data["options"]),
                        max((q["position"] for q in current), default=0) + 1,
                    ),
                )
            elif action == "edit":
                cur.execute(
                    """UPDATE survey_questions SET prompt=%s,kind=%s,required=%s,options=%s::jsonb
                               WHERE question_id=%s""",
                    (
                        data["prompt"],
                        data["kind"],
                        data["required"],
                        json.dumps(data["options"]),
                        qid,
                    ),
                )
            elif action in ("archive", "restore"):
                if question["archived"] == (action == "archive"):
                    raise HTTPException(
                        409, "Question is already in that state. Reload the questions."
                    )
                cur.execute(
                    "UPDATE survey_questions SET archived=%s WHERE question_id=%s",
                    (action == "archive", qid),
                )
            elif action == "move":
                if question["archived"] or body.get("direction") not in ("up", "down"):
                    raise HTTPException(
                        400, "Choose an active question and a move direction."
                    )
                index = active.index(question)
                other = index + (-1 if body["direction"] == "up" else 1)
                if not 0 <= other < len(active):
                    raise HTTPException(
                        400, "Question is already at the end of the list."
                    )
                active[index], active[other] = active[other], active[index]
                for pos, q in enumerate(active):
                    cur.execute(
                        "UPDATE survey_questions SET position=%s WHERE question_id=%s",
                        (pos, q["id"]),
                    )
            cur.execute(
                "UPDATE survey_state SET version=version+1 WHERE singleton=true"
            )
            cur.execute(
                """INSERT INTO survey_audit(actor_email,action,question_id,version)
                           VALUES (%s,%s,%s,%s)""",
                (actor, action, qid, version + 1),
            )
            return read_survey(cur, archived=True)
    finally:
        put_ops(conn)


def validate_answers(survey, body):
    if (
        type(body.get("survey_version")) is not int
        or body["survey_version"] != survey["version"]
    ):
        raise HTTPException(
            409,
            "The questions have changed. Reload the survey and review your answers.",
        )
    answers = body.get("answers", {})
    if not isinstance(answers, dict):
        raise HTTPException(400, "Answers must be an object.")
    if set(answers) - {q["id"] for q in survey["questions"]}:
        raise HTTPException(400, "An answer refers to a removed or unknown question.")
    status = body.get("contact_status", "answered")
    if status not in ("answered", "no_answer", "refused", "inaccessible"):
        raise HTTPException(400, "Choose a valid contact outcome.")
    if status != "answered" and answers:
        raise HTTPException(400, "Only conversations can contain survey answers.")
    snapshot = {}
    for q in survey["questions"]:
        value = answers.get(q["id"], "")
        if not isinstance(value, str) or len(value) > 2000:
            raise HTTPException(
                400, "Answers must be text of at most 2,000 characters."
            )
        value = value.strip()
        if status == "answered" and q["required"] and not value:
            raise HTTPException(400, f"Please answer: {q['prompt']}")
        if value and q["kind"] != "text" and value not in q["options"]:
            raise HTTPException(400, "Select one of the available answer choices.")
        if status == "answered":
            snapshot[q["id"]] = {
                k: q[k] for k in ("prompt", "kind", "options", "required")
            }
            snapshot[q["id"]]["answer"] = value
    notes = body.get("notes", "")
    if not isinstance(notes, str) or len(notes) > 2000:
        raise HTTPException(400, "Notes must be text of at most 2,000 characters.")
    return status, {
        "survey_version": survey["version"],
        "questions": snapshot,
        "notes": notes.strip(),
    }
