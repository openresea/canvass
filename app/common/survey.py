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
        raise HTTPException(400, "Please write a question of up to 300 characters.")
    if kind not in ("text", "single_choice", "yes_no") or type(required) is not bool:
        raise HTTPException(400, "Please choose an answer type, and whether an answer is required.")
    if kind == "single_choice":
        if not isinstance(options, list) or not 2 <= len(options) <= 12:
            raise HTTPException(400, "Please add between 2 and 12 answer choices.")
        if any(
            not isinstance(v, str) or not 1 <= len(v.strip()) <= 120 for v in options
        ):
            raise HTTPException(400, "Each answer choice can be up to 120 characters.")
        options = [v.strip() for v in options]
        if len(set(v.casefold() for v in options)) != len(options):
            raise HTTPException(400, "Two of the answer choices are the same. Please make each one different.")
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
        raise HTTPException(400, "Something went wrong there. Please reload the page and try again.")
    if action != "add":
        try:
            qid = str(uuid.UUID(str(qid)))
        except ValueError:
            raise HTTPException(400, "We couldn't find that question. Please reload and try again.")
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
                    "Someone else has just changed the questions. Please reload them before saving.",
                )
            current = read_survey(cur, archived=True)["questions"]
            active = [q for q in current if not q["archived"]]
            question = next((q for q in current if q["id"] == qid), None)
            if action != "add" and question is None:
                raise HTTPException(404, "We couldn't find that question. Please reload and try again.")
            if action in ("add", "restore") and len(active) >= 50:
                raise HTTPException(
                    400, "A survey can have up to 50 questions. Please remove one first."
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
                        409, "That question has already been changed. Please reload the questions."
                    )
                cur.execute(
                    "UPDATE survey_questions SET archived=%s WHERE question_id=%s",
                    (action == "archive", qid),
                )
            elif action == "move":
                if question["archived"] or body.get("direction") not in ("up", "down"):
                    raise HTTPException(
                        400, "Something went wrong there. Please reload the page and try again."
                    )
                index = active.index(question)
                other = index + (-1 if body["direction"] == "up" else 1)
                if not 0 <= other < len(active):
                    raise HTTPException(
                        400, "That question can't move any further."
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
            "The questions have just been updated. Please reload them and check your answers before saving.",
        )
    answers = body.get("answers", {})
    if not isinstance(answers, dict):
        raise HTTPException(400, "Something went wrong there. Please reload the page and try again.")
    if set(answers) - {q["id"] for q in survey["questions"]}:
        raise HTTPException(400, "One of these questions has been removed. Please reload the survey and check your answers.")
    status = body.get("contact_status", "answered")
    if status not in ("answered", "no_answer", "refused", "inaccessible"):
        raise HTTPException(400, "Please choose what happened at the door.")
    if status != "answered" and answers:
        raise HTTPException(400, "Answers can only be saved when you had a conversation.")
    snapshot = {}
    for q in survey["questions"]:
        value = answers.get(q["id"], "")
        if not isinstance(value, str) or len(value) > 2000:
            raise HTTPException(
                400, "Each answer can be up to 2,000 characters."
            )
        value = value.strip()
        if status == "answered" and q["required"] and not value:
            raise HTTPException(400, f"Please answer this question: {q['prompt']}")
        if value and q["kind"] != "text" and value not in q["options"]:
            raise HTTPException(400, "Please pick one of the answer choices.")
        if status == "answered":
            snapshot[q["id"]] = {
                k: q[k] for k in ("prompt", "kind", "options", "required")
            }
            snapshot[q["id"]]["answer"] = value
    notes = body.get("notes", "")
    if not isinstance(notes, str) or len(notes) > 2000:
        raise HTTPException(400, "Notes can be up to 2,000 characters.")
    return status, {
        "survey_version": survey["version"],
        "questions": snapshot,
        "notes": notes.strip(),
    }
