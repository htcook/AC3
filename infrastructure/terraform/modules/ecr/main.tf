# ─────────────────────────────────────────────────────────────────────────────
# ECR Module — Container Registry with Image Scanning
# FedRAMP High: Encryption at rest, vulnerability scanning, immutable tags
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_ecr_repository" "app" {
  name                 = "${var.project_name}-${var.environment}"
  image_tag_mutability = "IMMUTABLE" # FedRAMP: prevent tag overwriting

  image_scanning_configuration {
    scan_on_push = true # FedRAMP: SI-2 vulnerability scanning
  }

  encryption_configuration {
    encryption_type = "AES256"
  }

  tags = { Name = "${var.project_name}-${var.environment}-ecr" }
}

# Lifecycle policy — keep last 30 images, expire untagged after 7 days
resource "aws_ecr_lifecycle_policy" "app" {
  repository = aws_ecr_repository.app.name

  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Expire untagged images after 7 days"
        selection = {
          tagStatus   = "untagged"
          countType   = "sinceImagePushed"
          countUnit   = "days"
          countNumber = 7
        }
        action = { type = "expire" }
      },
      {
        rulePriority = 2
        description  = "Keep last 30 tagged images"
        selection = {
          tagStatus     = "tagged"
          tagPrefixList = ["sha-"]
          countType     = "imageCountMoreThan"
          countNumber   = 30
        }
        action = { type = "expire" }
      }
    ]
  })
}
