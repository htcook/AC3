#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# AC3 LocalStack S3 Initialization
# Creates local S3 buckets mirroring the AWS dev environment
# Activated with: docker compose --profile offline up
# ─────────────────────────────────────────────────────────────────────────────

echo "Creating AC3 S3 buckets in LocalStack..."

awslocal s3 mb s3://ac3-dev-evidence-808038814732
awslocal s3 mb s3://ac3-dev-reports-808038814732
awslocal s3 mb s3://ac3-dev-assets-808038814732
awslocal s3 mb s3://ac3-dev-codebuild-808038814732

echo "S3 buckets created:"
awslocal s3 ls

echo "LocalStack S3 initialization complete."
