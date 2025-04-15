$PROJECT_ID="astute-charter-213919"
$REGION = "us-central1"
$REPO = "qr-auth-repo"

# Build blockchain_node
docker build -t "$REGION-docker.pkg.dev/$PROJECT_ID/$REPO/blockchain_node" ../blockchain_node

# Push blockchain_node
docker push "$REGION-docker.pkg.dev/$PROJECT_ID/$REPO/blockchain_node"


# Build auth_service
docker build -t "$REGION-docker.pkg.dev/$PROJECT_ID/$REPO/auth_service" ../auth_service

# Push auth_service
docker push "$REGION-docker.pkg.dev/$PROJECT_ID/$REPO/auth_service"