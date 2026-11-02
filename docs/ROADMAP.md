# Roadmap

## Initial public alpha

Publish a downloadable source repository with issues, contribution instructions, synthetic fixtures, private vulnerability reporting and CI. Keep this version offline. Verify the canonical test/build job before presenting it as passing.

## Validate usefulness

Invite willing developers to try an API exploration or offline testing task. Record what they attempted, whether the output helped, and incorrect inferences. Publish only deidentified feedback with consent. Prioritize demonstrated problems over adding more features.

## Technical candidates

- Full OpenAPI document validation and more schema edge cases.
- Array/query and body-schema ambiguity, including reserved input names.
- More precise GraphQL parsing; inline GraphQL literals may contain secrets.
- Better route inference without combining unrelated literal resources.
- Explicit, separately requested multi-origin OpenAPI documents.
- Stronger compiled-bundle admission bounds and clearer CLI errors.
- A connection-bound, independently reviewed transport before considering live HTTP.

## Distribution

Start with GitHub source and tagged prereleases. Evaluate package-name availability, reproducible wheel installation and maintenance before any PyPI publication. No package-registry upload or automatic release credentials are configured.

Track genuine releases, accepted contributions and actual usage. Publishing a repository, adding templates or passing tests does not establish ecosystem impact for a sponsorship program.
