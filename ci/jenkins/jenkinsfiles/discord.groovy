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
    return [name: name, value: clip(value ?: 'n/a', 1024), inline: true]
}

// Progress bar of `done` out of `total`; never full while something is missing, so a single
// failure among hundreds of tests still shows.
def bar(int done, int total, int width = 10) {
    int filled = total == 0 ? 0 : (int) (done * width / total)
    if (done < total && filled == width) {
        filled = width - 1
    }
    def text = ''
    for (int i = 0; i < width; i++) {
        text += i < filled ? '█' : '░'
    }
    return text
}

// Discord rejects a description over 4096 characters and a field over 1024.
def clip(String text, int max) {
    return text.length() <= max ? text : text.substring(0, max - 1) + '…'
}

// Parses the `THEME`/`FAIL` lines of scripts/test-themes.sh. Plain loops: collection methods
// taking a closure misbehave under the CPS transform.
def parseThemes(String tsv) {
    def themes = []
    def failures = []
    for (line in (tsv ?: '').split('\n')) {
        def cols = line.split('\t')
        if (cols[0] == 'THEME' && cols.length == 6) {
            themes << [group: cols[1], name: cols[2], pass: cols[3] as int, fail: cols[4] as int, skip: cols[5] as int]
        } else if (cols[0] == 'FAIL' && cols.length == 2) {
            failures << cols[1]
        }
    }
    return [themes: themes, failures: failures]
}

// One code block per group of themes: a line per theme with its count and a bar, then the
// failing tests (first ten). Empty when the report has no theme, e.g. the build stopped early.
def testTables(Map parsed) {
    def groups = ['functional': 'FUNCTIONAL CASES', 'roundtrip': 'PROPERTY TESTS', 'integration': 'INTEGRATION', 'unit': 'UNIT TESTS']
    def text = ''
    for (entry in groups) {
        def lines = ''
        for (theme in parsed.themes) {
            if (theme.group != entry.key) {
                continue
            }
            int total = theme.pass + theme.fail + theme.skip
            def mark = theme.fail > 0 ? '✘' : '✔'
            def note = theme.fail > 0 ? "  ${theme.fail} failed" : (theme.skip > 0 ? "  ${theme.skip} skipped" : '')
            lines += "${mark} ${theme.name.padRight(9)} ${"${theme.pass}/${total}".padLeft(9)}  ${bar(theme.pass + theme.skip, total)}${note}\n"
        }
        if (lines) {
            text += "**${entry.value}**\n```\n${lines}```\n"
        }
    }
    if (parsed.failures) {
        def shown = ''
        int count = 0
        for (name in parsed.failures) {
            if (count++ == 10) {
                shown += "… and ${parsed.failures.size() - 10} more\n"
                break
            }
            shown += "${clip(name, 80)}\n"
        }
        text += "**FAILURES**\n```\n${shown}```\n"
    }
    return text
}

// Parses the report lines of scripts/bench-records.sh (`name median unit best <flag>`) into one
// code block per unit. `gain` is the median against the best ever, positive when better:
// `ms` is lower-is-better, every other unit higher-is-better.
def benchTables(String report) {
    def titles = ['MB/s': 'THROUGHPUT (MB/s)', 'ops/s': 'RSA (ops/s)', 'ms': 'PRIME GENERATION (ms)']
    def rows = [:]
    for (line in (report ?: '').split('\n')) {
        def cols = line.trim().split(/\s+/)
        if (cols.length < 5 || cols[3] != 'best') {
            continue
        }
        double median = cols[1] as double
        double best = cols[4] as double
        double gain = best == 0 ? 0 : (median - best) / best * 100
        if (cols[2] == 'ms') {
            gain = -gain
        }
        def flags = cols.length > 5 ? cols[5..-1].join(' ') : ''
        def mark = flags.startsWith('NEW PB') ? '▲' : (flags.startsWith('REGRESSION') ? '▼' : (flags == 'first run' ? '○' : '·'))
        def delta = flags == 'first run' ? 'first run' : (flags.startsWith('NEW PB') ? 'new best' : String.format('%+.1f%%', gain))
        def row = "${mark} ${cols[0].padRight(16)} ${String.format('%10.1f', median)}  ${delta}\n"
        rows[cols[2]] = (rows[cols[2]] ?: '') + row
    }
    def text = ''
    for (entry in titles) {
        if (rows[entry.key]) {
            text += "**${entry.value}**\n```\n${rows[entry.key]}```\n"
        }
    }
    return text
}

// Embed timestamps are ISO 8601 UTC.
def now() {
    return new Date().format("yyyy-MM-dd'T'HH:mm:ss'Z'", TimeZone.getTimeZone('UTC'))
}

def send(String description, List fields) {
    send(description: description, fields: fields)
}

// Options: description and fields (inline `field`s).
def send(Map options) {
    try {
        def result = currentBuild.currentResult
        def embed = [
            title: "${badge(result)} ${env.JOB_NAME} #${env.BUILD_NUMBER} · ${result.toLowerCase()}",
            url: env.BUILD_URL,
            color: color(result),
            description: clip(options.description ?: '', 4000),
            fields: options.fields ?: [],
            footer: [text: "took ${currentBuild.durationString.replace(' and counting', '')}"],
            timestamp: now()
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
