# GitHub Pages

[Zola - GitHub Pages](https://www.getzola.org/documentation/deployment/github-pages/)

## Deployment

### Create PAT (Personal Access Token)

1. [Settings](https://github.com/settings/)
2. [Developer settings](https://github.com/settings/apps)
3. Personal access tokens > [Fine-grained tokens](https://github.com/settings/tokens)
4. [Generate new token](https://github.com/settings/personal-access-tokens/new)
5. Grant **Public Repositories (read-only)** access
6. **Back up token** to Bitwarden

### Repository secrets

1. [Settings](https://github.com/marcellbarsony/marcellbarsony.github.io/settings)
2. Secrets and variable > [Actions](https://github.com/marcellbarsony/marcellbarsony.github.io/settings/secrets/actions)
3. [New repository secrets](https://github.com/marcellbarsony/marcellbarsony.github.io/settings/secrets/actions/new)
4. Name the secret `TOKEN` and paste the **PAT**

### GitHub Action

1. [Actions](https://github.com/marcellbarsony/marcellbarsony.github.io/actions)
2. [New workflow](https://github.com/marcellbarsony/marcellbarsony.github.io/actions/new)
3. set up a new workflow yourself
4. Paste the following template script

```yml
on: push
name: Build and deploy GH Pages
jobs:
  build:
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    steps:
      - name: checkout
        uses: actions/checkout@v4
      - name: build_and_deploy
        uses: shalzz/zola-deploy-action@v0.17.2
        env:
          # Target branch
          PAGES_BRANCH: gh-pages
          # Provide personal access token
          # TOKEN: ${{ secrets.TOKEN }}
          # Or if publishing to the same repo, use the automatic token
          TOKEN: ${{ secrets.GITHUB_TOKEN }}
```
5. Settings
6. Actions > General
7. Workflow permissions > Grant **Read and write permissions**
8. Tick **Allow GitHub Actions to create and approve pull requests**

### Build and deployment

1. Settings
2. Pages
3. Build and deployment
4. Source > **Deploy from a branch**
5. Branch > **gh-pages**
6. Branch > **/root**
