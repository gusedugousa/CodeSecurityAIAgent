# AWS Deployment (future target, optional)

The platform is cloud-agnostic; AWS is documented here purely as an alternative deployment
target alongside Azure, not a hard dependency.

Planned target shape:

- **Compute**: ECS Fargate (see `ecs-placeholder.tf`) or EKS.
- **Database**: Amazon RDS for PostgreSQL.
- **Cache/Queue**: Amazon ElastiCache for Redis, and/or Amazon SQS for the future job queue.
- **Object storage**: Amazon S3, implementing `app.persistence.object_store.ObjectStore`
  (see `S3CompatibleObjectStorePlaceholder`).
- **Observability**: OpenTelemetry Collector exporting to AWS CloudWatch / X-Ray.
- **Secrets**: AWS Secrets Manager, fronted by the `VaultMCPAdapter` extension point.

No AWS SDKs or credentials are required by the MVP.
