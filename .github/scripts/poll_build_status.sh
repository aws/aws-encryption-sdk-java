# Polls the provided CodeBuild batch ID until the build terminates
# Script terminates when the build status is not "IN_PROGRESS".
#
# Usage: ./poll_build_status.sh [batch-build-id]

BUILD_TIMEOUT_MINUTES=120
POLL_COUNTER=0

while [ $POLL_COUNTER -lt $BUILD_TIMEOUT_MINUTES ]; do
  BUILD_STATUS=$(aws codebuild batch-get-build-batches \
      --ids "$1" \
      | jq -r --arg BATCH_ID "$1" '.buildBatches[]
              | select(.id == $BATCH_ID)
              | .buildBatchStatus' )

  echo "Build status is $BUILD_STATUS after $POLL_COUNTER minutes"
  # If build succeeds, exit 0; Github will interpret 'exit 0' as successful job run
  if [ "$BUILD_STATUS" == "SUCCEEDED" ]; then
    exit 0
  fi

  # If build is not successful nor in-progress, it has either failed, timed-out, faulted, or been stopped.
  # Github will interpret 'exit 1' as job failure
  if [ "$BUILD_STATUS" != "IN_PROGRESS" ]; then
    exit 1
  fi

  ((POLL_COUNTER++))
  sleep 60
done

# If job does not report success within BUILD_TIMEOUT_MINUTES, fail Github job
exit 1;