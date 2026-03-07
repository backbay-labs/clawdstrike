# Evidence and Attestation

Fleet Security is not just about stopping bad behavior. It is also about being
able to prove what happened after the fact.

## Why This Matters

Agent incidents are often contested or confusing. A team may need to answer:

- which principal acted
- what policy and posture applied at the time
- which response action was taken
- whether the exported evidence was modified after the incident

## Cases and Bundles

Cases collect the investigation record. Evidence bundles are the portable
artifact you can hand to another team, an auditor, or a customer.

A useful mental model is:

- the case is the working folder
- the bundle is the signed package you can move elsewhere

## What Gets Attested

Evidence bundles include signed manifests so the receiving side can verify the
bundle without having to trust the live control plane blindly.

At a practical level, operators should care about three properties:

- the manifest identifies what the bundle is about
- the bundle contents are hashed in a stable way
- the manifest signature proves who signed it and when

## What Operators Should Do

- export evidence before closing important incidents
- keep case notes and attached artifacts clean enough that the bundle tells a coherent story
- verify bundle retention windows so evidence does not disappear unexpectedly

## Related Docs

- [Operator Guide](operator-guide.md)
- [Detection, Hunt, and Response](detection-response.md)
