prod:
	docker compose up -d --build

dev:
	docker compose --profile dev up --build

down:
	docker compose down

logs:
	docker compose logs -f

# Pull origin/main on dell01 and rebuild the production container there.
# The bare `git fetch origin` matters: the branch-qualified form only writes
# FETCH_HEAD, leaving origin/main unresolved on a fresh checkout.
deploy:
	ssh -A dell01 "cd ~/warehack-ing/mcfortigate \
	  && git fetch --quiet origin && git reset --hard origin/main \
	  && cd docs-site && docker compose up -d --build docs"

.PHONY: prod dev down logs deploy
