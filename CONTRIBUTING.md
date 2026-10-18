# Contributing

Thanks for your interest in Resea Canvass!

Bug reports and ideas are very welcome. Please open an issue, and use made-up data in any examples.

We're not able to accept code contributions just yet. We first need a contributor agreement that lets us keep the project free for non-commercial use while also offering separate commercial licences. Please don't send code written by someone else without their permission.

If you're working on your own copy:

- Work on a separate branch and use made-up test data.
- Install `requirements-dev.txt` and run the quick tests. If you touch sign-in, permissions, questions or saving visits, run the PostgreSQL and browser tests too (see the README for the throwaway database they need).
- Keep question wording and answer choices configurable. Don't add organisation names, real addresses, account details or secrets as defaults.
- When changing how questions work, make sure past answers keep the wording they were given with.
- Check permissions on the server, not just in the page.
- Keep the licence and notice files intact.
