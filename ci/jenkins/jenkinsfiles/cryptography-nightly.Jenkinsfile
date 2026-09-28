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

pipeline {
    agent { label 'rust-agent' }

    options {
        timeout(time: 60, unit: 'MINUTES')
        buildDiscarder(logRotator(numToKeepStr: '30'))
    }

    environment {
        BENCH_SAMPLES = '10'
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
                sh 'cargo test --workspace --release -- --include-ignored'
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'target/bench/*.csv', allowEmptyArchive: true
            cleanWs()
        }
    }
}
