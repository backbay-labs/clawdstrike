# Sidebar Intelligence

> **Status:** Active | **Date:** 2026-03-08
> **Audience:** Desktop, product, interaction, and swarm implementers
> **Scope:** Turn the Huntronomer workbench sidebar into a native anticipatory surface that feels
> "before I thought of it" without taking destructive action automatically

This initiative extends the existing Intent Gravity groundwork into a coordinated delivery program.
The sidebar is no longer treated as an isolated drawer. It becomes the visible expression of a
predictive interaction model that also shapes adjacent surfaces when the operator is clearly moving
toward a likely next step.

## Reading Order

1. [Sidebar Interaction Spec](./sidebar-interaction-spec.md)
2. [Swarm Plan](./swarm-plan.md)
3. [Intent Gravity Implementation](../intent-gravity-implementation.md)
4. [Huntronomer Initiative Index](../README.md)

## Delivery Goal

The finished sidebar should:

- wake up while visually closed before the operator explicitly opens it
- reorder and expand lens sections based on context, phase, and confidence
- explain why it is promoting a target, section, or surface
- execute semantic drop intent instead of showing decorative drop pills only
- preserve adjacent proof and context surfaces when predictive open behavior matters

## Landed So Far

- The collapsed rail now holds a live hot zone and spring-opens on dwell instead of staying dead at
  width `0`.
- Every lens now renders through the section-registry contract, so the director can reorder,
  promote, hide, and expand sections natively.
- Smart bucket semantics now preview and execute through shared drag state.
- Bottom panel and inspector promotions now come from the same director state as the sidebar.
- `typecheck`, `test`, and `build` are green for the current slice.

## Shared Guardrails

- Low confidence only hints and highlights.
- Medium confidence may pre-open the sidebar and promote one section.
- High confidence may spring-load the likely lens and deeper subtargets.
- No anticipatory behavior commits destructive work on behalf of the operator.
- Shared integration files stay orchestrator-owned during swarm execution.
