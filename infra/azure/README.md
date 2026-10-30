# Azure Deployment (future target)

This directory is a placeholder for Azure-ready deployment of the platform. The MVP runs
cloud-agnostically in Docker; nothing here is required to run it locally.

Planned target shape:

- **Compute**: Azure Container Apps (see `container-apps-placeholder.bicep`) or AKS for
  higher-scale deployments.
- **Database**: Azure Database for PostgreSQL Flexible Server, replacing the SQLite fallback.
- **Cache/Queue**: Azure Cache for Redis, and/or Azure Service Bus for the future job queue.
- **Object storage**: Azure Blob Storage, implementing `app.persistence.object_store.ObjectStore`
  (see `AzureBlobObjectStorePlaceholder`).
- **Vector DB**: Azure AI Search, implementing `app.persistence.vector_store.VectorStore`.
- **Secrets**: Azure Key Vault, fronted by the `VaultMCPAdapter` extension point.
- **Observability**: OpenTelemetry Collector exporting to Azure Monitor / Application Insights
  in addition to (or instead of) the local Grafana/Prometheus/Loki/Tempo stack.
- **AuthN/AuthZ**: Microsoft Entra ID (Azure AD) backing the `AuthenticationPlaceholder` /
  `AuthorizationPlaceholder` interfaces in `app/core/security.py`.

No Azure SDKs or credentials are required by the MVP. Everything above is an interface the
MVP already exposes an extension point for — see `docs/extension_points.md`.
