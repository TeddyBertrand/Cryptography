// Shared Discord build report, `load`ed from the workspace by both
// Jenkinsfiles in `post { always }` (so before `cleanup { cleanWs() }`).
// Best-effort: a missing webhook, a Discord outage or a bad payload never
// changes the build result.
//
// The payload is built with JsonOutput and sent from a file, and the webhook
// URL comes from withCredentials, so neither goes through Groovy string
// interpolation into the shell script.

import groovy.json.JsonOutput

// Unicode escapes rather than :shortcodes:, which Discord doesn't expand in
// embed titles.
def badge(String result) {
    switch (result) {
        case 'SUCCESS': return '🟢'
        case 'UNSTABLE': return '🟡'
        case 'FAILURE': return '🔴'
        default: return '⚪'
    }
}

def color(String result) {
    switch (result) {
        case 'SUCCESS': return 0x2ECC71
        case 'UNSTABLE': return 0xF1C40F
        case 'FAILURE': return 0xE74C3C
        default: return 0x95A5A6
    }
}

// Inline embed field; Discord rejects empty values.
def field(String name, String value) {
    return [name: name, value: value ?: 'n/a', inline: true]
}

def send(String description, List fields) {
    try {
        def result = currentBuild.currentResult
        def embed = [
            title: "${badge(result)} ${env.JOB_NAME} #${env.BUILD_NUMBER}: ${result.toLowerCase()}",
            url: env.BUILD_URL,
            color: color(result),
            description: description,
            fields: fields,
            footer: [text: "took ${currentBuild.durationString.replace(' and counting', '')}"]
        ]
        writeFile file: 'discord-payload.json', text: JsonOutput.toJson([embeds: [embed]]), encoding: 'UTF-8'
        withCredentials([string(credentialsId: 'discord-webhook-url', variable: 'DISCORD_WEBHOOK_URL')]) {
            sh '''
                if [ -z "$DISCORD_WEBHOOK_URL" ]; then
                    echo "Discord webhook not configured, skipping"
                    exit 0
                fi
                curl -sSf -H 'Content-Type: application/json' -d @discord-payload.json "$DISCORD_WEBHOOK_URL"
            '''
        }
    } catch (err) {
        echo "Discord report not sent: ${err.message}"
    }
}

return this
