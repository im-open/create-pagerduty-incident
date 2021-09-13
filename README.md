# create-pagerduty-incident

This action will create a PagerDuty incident.  Only one service can be targeted at a time.

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
      - uses: actions/checkout@v2

      - id: deployed-checksum
        run: ./generate-checksum-against-deployed-code.sh

      - id: compare-checksums
        run: ./compare-checksums -deployedChecksum ${{ steps.deployed-checksum.outputs.CHECKSUM }}

      - name: Create a PagerDuty Incident
        if: steps.compare-checksums.outputs.MATCH == 'false'
        uses: im-open/create-pagerduty-incident@v1.0.0
        with:
          pagerduty-api-key: ${{secrets.PAGERDUTY_API_KEY}}
          email: bob@office.com
          service-id: 'P0ABCDE'
          title: 'The deployed code does not match the expected version'
          body: 'Find more information at: https://github.com/${{ github.repository }}/actions/runs/${{ github.run_id }}'
      
```

## Recompiling

If changes are made to the action's code in this repository, or its dependencies, you will need to re-compile the
action.

```sh
# Installs dependencies and bundles the code
npm run build

# Bundle the code (if dependencies are already installed)
npm run bundle
```

These commands utilize [esbuild](https://esbuild.github.io/getting-started/#bundling-for-node) to bundle the action and
its dependencies into a single file located in the `dist` folder.

## Code of Conduct

This project has adopted the [im-open's Code of Conduct](https://github.com/im-open/.github/blob/master/CODE_OF_CONDUCT.md).

## License

Copyright &copy; 2021, Extend Health, LLC. Code released under the [MIT license](LICENSE).
