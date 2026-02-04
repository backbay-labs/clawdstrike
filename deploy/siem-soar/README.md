# SIEM/SOAR Integration Assets

This folder contains ready-to-import/ready-to-apply artifacts referenced by `docs/plans/siem-soar/*`:

- **Splunk**: `props.conf`, `transforms.conf`, lookup CSVs, and a simple dashboard XML.
- **Elastic**: example ILM policy + composable index template JSON + detection rule templates.
- **Datadog**: example dashboard + monitor JSON templates.
- **Sumo Logic**: field extraction rules, saved search/alert templates, and a dashboard template.

These are **templates**: you may need to adjust index names, categories, tags, and destination IDs (PagerDuty services, Sumo webhooks, etc.) to match your environment.
