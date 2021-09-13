const core = require('@actions/core');
const axios = require('axios');

const requiredArgOptions = {
  required: true,
  trimWhitespace: true
};

const pagerdutyApiKey = core.getInput('pagerduty-api-key', requiredArgOptions);
const email = core.getInput('email', requiredArgOptions);
const serviceId = core.getInput('service-id', requiredArgOptions);
const title = core.getInput('title', requiredArgOptions);
const body = core.getInput('body');

core.info(`Creating PagerDuty Incident for:  ${title}`);

try {
  let incidentDetails = {
    incident: {
      type: 'incident',
      title: title,
      service: {
        id: serviceId,
        type: 'service'
      }
    }
  };
  if (body && body.length > 0) {
    incidentDetails.incident.body = {
      type: 'incident_body',
      details: body
    };
  }

  axios({
    method: 'post',
    url: 'https://api.pagerduty.com/incidents',
    headers: {
      'content-type': 'application/json',
      authorization: `Token token=${pagerdutyApiKey}`,
      accept: 'application/vnd.pagerduty+json;version=2',
      from: email
    },
    data: JSON.stringify(incidentDetails)
  })
    .then(function () {
      core.info('The incident was successfully created:');
    })
    .catch(function (error) {
      core.setFailed(`An error occurred creating the incident: ${error}`);
      return;
    });
} catch (error) {
  core.setFailed(`An error occurred while creating the incident: ${error}`);
}
