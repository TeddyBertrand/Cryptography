import groovy.transform.Field

// Nightly run (cron trigger in seed-job.yaml): benchmarks and the slow
// release suite, too slow for every push. Bench medians are plotted build
// over build by the Plot plugin.

// Plot plugin CSVs hold one column per series and a single row of values;
// `bench` prints one row per benchmark, so the pivot stage builds one such
// file per unit. `csvFileName` is the plot's history, kept in the job dir so
// it survives cleanWs and build rotation. Log scale: series on one plot span
// orders of magnitude (XOR ~600 MB/s next to AES ~1 MB/s).
def plotBench(String file, String title, String unit) {
    plot(
        csvFileName: "plot-bench-${file}.csv",
        csvSeries: [[file: "target/bench/${file}.csv", inclusionFlag: 'OFF', displayTableFlag: false]],
        group: 'Benchmarks',
        title: title,
        yaxis: unit,
        style: 'line',
        logarithmic: true,
        numBuilds: '60'
    )
}

// Filled by the Records and Stress tests stages for the Discord report;
// @Field script fields rather than locals so every stage and method sees
// them (a bare assignment would go through the binding, which Jenkins warns
// about). Null when the build stops before their stage.
@Field def benchReport = null
@Field def stressResult = null

// Best-effort: see discord.groovy.
def reportDiscord() {
    try {
        // Plain loop: collection methods taking a closure (count, findAll)
        // misbehave under the CPS transform.
        def records = 0
        def regressions = 0
        for (line in (benchReport ?: '').split('\n')) {
            if (line.contains('NEW PB')) records++
            if (line.contains('REGRESSION')) regressions++
        }
        def description = benchReport ? "```\n${benchReport.trim()}\n```" : 'Benchmarks not run'
        def discord = load 'ci/jenkins/jenkinsfiles/discord.groovy'
        discord.send(description, [
            discord.field('Stress tests', stressResult ?: 'not run'),
            discord.field('New PBs', "${records}"),
            discord.field('Regressions', "${regressions}")
        ])
    } catch (err) {
        echo "Discord report not sent: ${err.message}"
    }
}

pipeline {
    agent { label 'rust-agent' }

    options {
        timeout(time: 60, unit: 'MINUTES')
        buildDiscarder(logRotator(numToKeepStr: '30'))
    }

    environment {
        BENCH_SAMPLES = '10'
        // Best-ever medians, outside the workspace (cleanWs) but inside the
        // agent's workDir, which is the persistent rust_agent_workspace
        // volume (docker-compose.yml), so records survive builds and restarts.
        BENCH_RECORDS = '/home/jenkins/agent/bench-records/cryptography-nightly.csv'
        // Roundtrip property cases per cryptosystem in the Stress tests stage,
        // 100x the per-PR default (crates/my_pgp/tests/roundtrip/prng.rs).
        PROPERTY_CASES = '100000'
    }

    stages {
        stage('Benchmark') {
            steps {
                sh '''
                    mkdir -p target/bench
                    cargo run --release --bin bench "$BENCH_SAMPLES" > target/bench/bench.csv
                '''
            }
        }
        stage('Records') {
            steps {
                script {
                    benchReport = sh(
                        script: 'sh ci/jenkins/scripts/bench-records.sh target/bench/bench.csv "$BENCH_RECORDS"',
                        returnStdout: true
                    )
                }
            }
        }
        stage('Plot') {
            steps {
                sh '''
                    pivot() {
                        awk -F, -v unit="$1" '
                            NR > 1 && $2 == unit { names = names sep $1; values = values sep $4; sep = "," }
                            END { print names; print values }
                        ' target/bench/bench.csv > "target/bench/$2.csv"
                    }
                    pivot 'MB/s' throughput
                    pivot 'ops/s' rsa
                    pivot 'ms' prime
                '''
                plotBench('throughput', 'Symmetric cipher throughput', 'MB/s')
                plotBench('rsa', 'RSA operations', 'ops/s')
                plotBench('prime', 'Prime generation time', 'ms')
            }
        }
        stage('Stress tests') {
            steps {
                script {
                    stressResult = 'failed'
                    sh 'cargo test --workspace --release -- --include-ignored'
                    stressResult = 'passed'
                }
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'target/bench/*.csv', allowEmptyArchive: true
            reportDiscord()
        }
        // cleanup runs after every other post condition, so the report
        // above still has the workspace (discord.groovy).
        cleanup {
            cleanWs()
        }
    }
}
