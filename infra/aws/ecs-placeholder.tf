# Placeholder Terraform for a future ECS Fargate deployment of the platform.
# Not wired into any deployment pipeline yet — documents the intended shape only.
# See infra/aws/README.md and docs/extension_points.md.

variable "image_uri" {
  type    = string
  default = "REPLACE_ME.dkr.ecr.us-east-1.amazonaws.com/governed-ai-code-security:latest"
}

variable "database_url_secret_arn" {
  type = string
}

resource "aws_ecs_cluster" "this" {
  name = "governed-ai-code-security"
}

resource "aws_ecs_task_definition" "app" {
  family                   = "governed-ai-code-security"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "512"
  memory                   = "1024"

  container_definitions = jsonencode([
    {
      name  = "app"
      image = var.image_uri
      portMappings = [{ containerPort = 8000 }]
      secrets = [
        {
          name      = "APP_DATABASE_URL"
          valueFrom = var.database_url_secret_arn
        }
      ]
    }
  ])
}

resource "aws_ecs_service" "app" {
  name            = "governed-ai-code-security"
  cluster         = aws_ecs_cluster.this.id
  task_definition = aws_ecs_task_definition.app.arn
  desired_count   = 1
  launch_type     = "FARGATE"
}
