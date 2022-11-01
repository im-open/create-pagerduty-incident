# create-pagerduty-incident

This action will create a PagerDuty incident.  Only one service can be targeted at a time.
    
## Index 

- [Inputs](#inputs)
- [Outputs](#outputs)
- [Example](#example)
- [Contributing](#contributing)
  - [Recompiling](#recompiling)
  - [Incrementing the Version](#incrementing-the-version)
- [Code of Conduct](#code-of-conduct)
- [License](#license)
  
## Inputs
| Parameter           | Is Required | Description                                                                                |
| ------------------- | ----------- | ------------------------------------------------------------------------------------------ |
| `pagerduty-api-key` | true        | The PagerDuty API Key that allows access to your services.                                 |
| `email`             | true        | The email address of a valid PagerDuty user on the account associated with the auth token. |
| `service-id`        | true        | The PagerDuty Service ID to create the incident for.                                       |
| `title`             | true        | The title of the PagerDuty Incident that will be created.                                  |
| `body`              | false       | The body of the PagerDuty Incident that will be created.                                   |

## Outputs
No outputs


## Example

```yml
  jobs:
    validate-deployed-code:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - id: deployed-checksum
        run: ./generate-checksum-against-deployed-code.sh

      - id: compare-checksums
        run: ./compare-checksums -deployedChecksum ${{ steps.deployed-checksum.outputs.CHECKSUM }}

      - name: Create a PagerDuty Incident
        if: steps.compare-checksums.outputs.MATCH == 'false'
        uses: im-open/create-pagerduty-incident@v1.1.1
        with:
          pagerduty-api-key: ${{secrets.PAGERDUTY_API_KEY}}
          email: bob@office.com
          service-id: 'P0ABCDE'
          title: 'The deployed code does not match the expected version'
          body: 'Find more information at: https://github.com/${{ github.repository }}/actions/runs/${{ github.run_id }}'
      
```

## Contributing

When creating new PRs please ensure:
1. The action has been recompiled.  See the [Recompiling](#recompiling) section below for more details.
2. For major or minor changes, at least one of the commit messages contains the appropriate `+semver:` keywords listed under [Incrementing the Version](#incrementing-the-version).
3. The `README.md` example has been updated with the new version.  See [Incrementing the Version](#incrementing-the-version).
4. The action code does not contain sensitive information.

### Recompiling

If changes are made to the action's code in this repository, or its dependencies, you will need to re-compile the action.

```sh
# Installs dependencies and bundles the code
npm run build

# Bundle the code (if dependencies are already installed)
npm run bundle
```

These commands utilize [esbuild](https://esbuild.github.io/getting-started/#bundling-for-node) to bundle the action and
its dependencies into a single file located in the `dist` folder.

### Incrementing the Version

This action uses [git-version-lite] to examine commit messages to determine whether to perform a major, minor or patch increment on merge.  The following table provides the fragment that should be included in a commit message to active different increment strategies.
| Increment Type | Commit Message Fragment                     |
| -------------- | ------------------------------------------- |
| major          | +semver:breaking                            |
| major          | +semver:major                               |
| minor          | +semver:feature                             |
| minor          | +semver:minor                               |
| patch          | *default increment type, no comment needed* |

## Code of Conduct

This project has adopted the [im-open's Code of Conduct](https://github.com/im-open/.github/blob/master/CODE_OF_CONDUCT.md).

## License

Copyright &copy; 2021, Extend Health, LLC. Code released under the [MIT license](LICENSE).

[git-version-lite]: https://github.com/im-open/git-version-lite