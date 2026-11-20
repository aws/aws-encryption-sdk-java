# Starts a CodeBuild batch with provided source version
# Returns build batch ID for build
#
# Usage: ./start_codebuild_batch.sh [source_version]
aws codebuild start-build-batch \
    --region us-west-2 \
    --project-name AWS-ESDK-Java-CI \
    --source-version "$1" \
    | jq -r '.buildBatch.id'