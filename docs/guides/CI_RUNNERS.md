# CI runners

The container workflow uses GitHub-hosted `ubuntu-latest` runners. It builds the disposable `checks` image, runs its selected boundary tests, builds and starts the two application services with synthetic storage, verifies HTTP health and the service count, and stops the services. GitHub provides a fresh hosted environment for each job, so contributor computers can be powered off or disconnected. See [GitHub-hosted runners](https://docs.github.com/en/actions/how-tos/manage-runners/github-hosted-runners/use-github-hosted-runners).

The workflow grants `contents: read`, pins checkout and disables persisted checkout credentials. It generates a disposable database password and does not reference operator secrets, upload artifacts, publish images or deploy the application. Public dependency/image downloads remain necessary. Container CI success covers the selected tests and startup; it does not prove the full database suite, browser acceptance, persistence after recreation or live Microsoft collection.

The current workflow accepts pull requests targeting `main`, pushes to `main`, and manual dispatch. `main` is the release-ready branch and the target for future authorized pushes. Restricting push checks to `main` avoids duplicate feature-branch push/PR builds while retaining the same test selection, cancellation and timeout. The optional native test harness is a contributor tool, not a registered runner or supported product launcher. The obsolete `sprint-one` branch and legacy VM recovery/storage helpers have been removed. Source cleanup does not deregister a runner, remove a host service or delete runtime data.

## Private infrastructure

No current synthetic/public CI job requires a private runner. A container runner on a contributor computer still depends on that computer's uptime and network connection. Prefer hosted container checks for ordinary contributions.

If a future approved integration needs private connectivity or evidence, keep provisioning, registration credentials, secrets and logs in a separate private infrastructure repository. Register its runner only there, run reviewed exact product commits, and exclude public pull-request code. Prefer an ephemeral one-job runner with disposable job storage on available dedicated infrastructure. Container isolation alone does not protect the host: access to a host Docker socket or privileged Docker-in-Docker grants broad authority. See [runner access](https://docs.github.com/en/actions/how-tos/manage-runners/self-hosted-runners/manage-access), [ephemeral runners](https://docs.github.com/en/actions/reference/runners/self-hosted-runners) and [ARC container modes](https://docs.github.com/en/actions/how-tos/manage-runners/use-actions-runner-controller/deploy-runner-scale-sets).

## Retiring an old registration

Local inspection found no installed `TriageMateRunner` WSL distribution or Windows/Ubuntu GitHub runner service on the inspected computer. That does not establish that GitHub's registration or a separate historical host has been removed. Check the repository's Settings > Actions > Runners and the original host before separately authorizing de-registration or infrastructure cleanup. Source cleanup does not remove a runner registration, service, disk, credentials or retained data.

Before making an existing repository public, review its historical Actions logs and artifacts along with source history. Keeping private infrastructure elsewhere prevents future job routing to it; it does not hide logs already stored in the product repository.
