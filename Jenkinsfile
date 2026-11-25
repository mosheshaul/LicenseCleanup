// JetBrains license cleanup - Declarative Pipeline
//
// Runs monthly (1st of the month, 02:00-02:59 in CRON_TZ) and on demand.
// Scheduled runs IGNORE build parameters and use only the reviewed
// config/config.yaml (execution.scheduled_mode). Manual runs default to DRY_RUN.
//
// Python exit codes: 0 = OK, 1 = partial failure / safety gate (UNSTABLE), 2 = critical (FAILURE).

import groovy.transform.Field

// ---- Site-specific settings (non-secret) -----------------------------------
// @Field makes these visible inside the helper methods below.
@Field def CRON_TZ       = 'Etc/UTC'            // e.g. 'Asia/Jerusalem', 'Europe/London'
@Field def CRON_SPEC     = 'H 2 1 * *'          // minute hashed within 02:xx on day 1 of every month
@Field def AGENT_LABEL   = 'linux && python3'   // agent with Python 3.10+ and network access to JetBrains + DCs
@Field def PYTHON_BIN    = 'python3'

// Credential IDs in Jenkins Credentials Manager.
@Field def CRED_JB_TOKEN    = 'jetbrains-api-token'      // Secret text
@Field def CRED_JB_CUSTOMER = 'jetbrains-customer-code'  // Secret text
@Field def CRED_AD          = 'ad-service-account'       // Username with password
@Field def CRED_SLACK       = 'slack-webhook-url'        // Secret text (optional)
@Field def CRED_SMTP        = 'smtp-relay-account'       // Username with password (optional)

// Runs a CLI stage and maps its exit code to a Jenkins result.
def cli(String command) {
    def rc = sh(returnStatus: true, label: "license-cleanup ${command}", script: """
        . .venv/bin/activate
        python -m license_cleanup ${command} \
          --config config/config.yaml \
          --state-dir "\$STATE_DIR" --log-dir logs \
          --trigger "\$RUN_TRIGGER"
    """)
    if (rc == 1) {
        unstable("license-cleanup ${command} reported a partial failure or blocked safety gate")
        return 1
    }
    if (rc != 0) {
        env.CRITICAL_FAILURE = 'true'
        error("license-cleanup ${command} failed critically (exit ${rc})")
    }
    return 0
}

def jetbrainsCreds() {
    return [string(credentialsId: CRED_JB_TOKEN, variable: 'JETBRAINS_API_TOKEN'),
            string(credentialsId: CRED_JB_CUSTOMER, variable: 'JETBRAINS_CUSTOMER_CODE')]
}

def adCreds() {
    return [usernamePassword(credentialsId: CRED_AD, usernameVariable: 'AD_BIND_USER', passwordVariable: 'AD_BIND_PASSWORD')]
}

def notOk() { return env.CRITICAL_FAILURE == 'true' }

pipeline {
    agent { label AGENT_LABEL }

    triggers {
        cron("TZ=${CRON_TZ}\n${CRON_SPEC}")
    }

    options {
        timeout(time: 2, unit: 'HOURS')
        timestamps()
        disableConcurrentBuilds()
        buildDiscarder(logRotator(numToKeepStr: '36', daysToKeepStr: '1095', artifactNumToKeepStr: '24', artifactDaysToKeepStr: '730'))
        skipDefaultCheckout(true)
    }

    parameters {
        booleanParam(name: 'DRY_RUN', defaultValue: true, description: 'Manual runs only. Uncheck to revoke (requires execution.production_enabled: true in config). Ignored by scheduled runs.')
        string(name: 'INACTIVITY_MONTHS', defaultValue: '6', description: 'Calendar months without product usage before a license is considered inactive (manual runs only).')
        booleanParam(name: 'REVOKE_DISABLED_USERS', defaultValue: true, description: 'Revoke licenses of users disabled in Active Directory (manual runs only).')
        booleanParam(name: 'REVOKE_INACTIVE_USERS', defaultValue: true, description: 'Revoke licenses unused for INACTIVITY_MONTHS (manual runs only).')
        string(name: 'MAX_REVOCATIONS', defaultValue: '20', description: 'Abort if more revocations are proposed (capped by safety.hard_max_revocations).')
        string(name: 'MAX_REVOCATION_PERCENT', defaultValue: '10', description: 'Abort if more than this % of assigned licenses would be revoked.')
        choice(name: 'LOG_LEVEL', choices: ['INFO', 'DEBUG', 'WARNING', 'ERROR'], description: 'Log verbosity.')
    }

    environment {
        STATE_DIR = "${WORKSPACE}/.state"
        PIP_DISABLE_PIP_VERSION_CHECK = '1'
        PYTHONDONTWRITEBYTECODE = '1'
        // Corporate proxy / CA (uncomment and adjust if required):
        // HTTPS_PROXY = 'http://proxy.example.com:8080'
        // NO_PROXY    = '.corp.example.com'
        // REQUESTS_CA_BUNDLE = '/etc/ssl/certs/corp-ca-bundle.pem'
    }

    stages {
        stage('1. Checkout source code') {
            steps {
                checkout scm
                script {
                    def timer = currentBuild.getBuildCauses('hudson.triggers.TimerTrigger$TimerTriggerCause')
                    env.RUN_TRIGGER = timer ? 'scheduled' : 'manual'
                    echo "Trigger: ${env.RUN_TRIGGER}"
                }
            }
        }

        stage('2. Prepare Python environment') {
            steps {
                sh label: 'Create virtualenv', script: '''
                    set -eu
                    rm -rf .venv .state
                    ''' + PYTHON_BIN + ''' -m venv .venv
                    . .venv/bin/activate
                    python --version
                '''
            }
        }

        stage('3. Install dependencies') {
            steps {
                sh label: 'pip install', script: '''
                    set -eu
                    . .venv/bin/activate
                    pip install --quiet -r requirements-dev.txt
                    pip install --quiet --no-deps -e .
                '''
                script {
                    def audit = sh(returnStatus: true, label: 'Dependency vulnerability scan', script: '''
                        . .venv/bin/activate
                        pip-audit -r requirements.txt --progress-spinner off
                    ''')
                    if (audit != 0) {
                        unstable('pip-audit reported vulnerable dependencies (or could not reach the vulnerability database)')
                    }
                }
            }
        }

        stage('4. Run automated tests') {
            steps {
                sh label: 'pytest', script: '''
                    set -eu
                    . .venv/bin/activate
                    python -m pytest --junitxml=reports/junit.xml -q
                '''
            }
            post { always { junit allowEmptyResults: true, testResults: 'reports/junit.xml' } }
        }

        stage('5. Validate configuration') {
            steps {
                script {
                    // Manual runs pass parameters; scheduled runs ignore them (approved config only).
                    def rc = sh(returnStatus: true, label: 'license-cleanup init', script: '''
                        . .venv/bin/activate
                        python -m license_cleanup init \
                          --config config/config.yaml --state-dir "$STATE_DIR" --log-dir logs \
                          --trigger "$RUN_TRIGGER" \
                          --execution-id "jenkins-${BUILD_NUMBER}-$(date -u +%Y%m%dT%H%M%SZ)" \
                          --dry-run "$DRY_RUN" \
                          --inactivity-months "$INACTIVITY_MONTHS" \
                          --revoke-disabled-users "$REVOKE_DISABLED_USERS" \
                          --revoke-inactive-users "$REVOKE_INACTIVE_USERS" \
                          --max-revocations "$MAX_REVOCATIONS" \
                          --max-revocation-percent "$MAX_REVOCATION_PERCENT" \
                          --log-level "$LOG_LEVEL"
                    ''')
                    if (rc != 0) {
                        env.CRITICAL_FAILURE = 'true'
                        error('Configuration or execution-mode validation failed')
                    }
                    cli('validate-config')
                    def ctx = readJSON(file: "${env.STATE_DIR}/context.json")
                    env.EXECUTION_ID = ctx.execution_id
                    env.EFFECTIVE_DRY_RUN = ctx.dry_run.toString()
                    currentBuild.description = "${ctx.dry_run ? 'DRY RUN' : 'PRODUCTION'} (${env.RUN_TRIGGER})"
                }
            }
        }

        stage('6. Validate JetBrains API connectivity') {
            when { expression { !notOk() } }
            steps { withCredentials(jetbrainsCreds()) { script { cli('check-jetbrains') } } }
        }

        stage('7. Validate Active Directory connectivity') {
            when { expression { !notOk() } }
            steps { withCredentials(adCreds()) { script { cli('check-ad') } } }
        }

        stage('8. Retrieve JetBrains license inventory') {
            when { expression { !notOk() } }
            steps { withCredentials(jetbrainsCreds()) { script { cli('inventory') } } }
        }

        stage('9. Match users against Active Directory') {
            when { expression { !notOk() } }
            steps { withCredentials(adCreds()) { script { cli('match-ad') } } }
        }

        stage('10. Analyze product usage and inactivity') {
            when { expression { !notOk() } }
            steps { script { cli('analyze') } }
        }

        stage('11. Generate proposed revocation plan') {
            when { expression { !notOk() } }
            steps { script { cli('plan') } }
        }

        stage('12. Validate safety thresholds') {
            when { expression { !notOk() } }
            steps { script { env.SAFETY_BLOCKED = (cli('safety-check') != 0).toString() } }
        }

        stage('13. Revoke eligible licenses') {
            when { expression { !notOk() } }
            steps {
                script {
                    if (env.EFFECTIVE_DRY_RUN == 'true') {
                        echo 'DRY RUN: no licenses will be revoked.'
                        cli('revoke')
                    } else if (env.SAFETY_BLOCKED == 'true') {
                        echo 'Safety gate blocked this run: skipping all revocations.'
                    } else {
                        withCredentials(jetbrainsCreds() + adCreds()) { cli('revoke') }
                    }
                }
            }
        }

        stage('14. Verify revocation results') {
            when { expression { !notOk() && env.EFFECTIVE_DRY_RUN == 'false' && env.SAFETY_BLOCKED != 'true' } }
            steps { withCredentials(jetbrainsCreds()) { script { cli('verify') } } }
        }
    }

    post {
        always {
            script {
                // 15. Generate final reports (runs even after a critical failure).
                stage('15. Generate final reports') {
                    if (fileExists("${env.STATE_DIR}/context.json")) {
                        def rc = sh(returnStatus: true, label: 'license-cleanup report', script: '''
                            . .venv/bin/activate
                            python -m license_cleanup report --config config/config.yaml --state-dir "$STATE_DIR" --log-dir logs
                        ''')
                        if (rc == 1 && currentBuild.currentResult == 'SUCCESS') { currentBuild.result = 'UNSTABLE' }
                        if (rc >= 2) { currentBuild.result = 'FAILURE' }
                    } else {
                        echo 'No execution context: the run failed before initialisation.'
                    }
                }
                // 16. Archive build artifacts (reports contain personal data: restrict job read access).
                stage('16. Archive build artifacts') {
                    archiveArtifacts artifacts: 'reports/**/*.csv, reports/**/*.json, logs/*.log', allowEmptyArchive: true, fingerprint: true
                }
                // 17. Send execution summary (aggregates only).
                stage('17. Send execution summary') {
                    if (fileExists("${env.STATE_DIR}/context.json")) {
                        def notifyCmd = '''
                            . .venv/bin/activate
                            python -m license_cleanup notify --config config/config.yaml --state-dir "$STATE_DIR" --log-dir logs || true
                        '''
                        try {
                            withCredentials([string(credentialsId: CRED_SLACK, variable: 'SLACK_WEBHOOK_URL'),
                                             usernamePassword(credentialsId: CRED_SMTP, usernameVariable: 'SMTP_USER', passwordVariable: 'SMTP_PASSWORD')]) {
                                sh(label: 'license-cleanup notify', script: notifyCmd)
                            }
                        } catch (err) {
                            echo "Optional notification credentials not configured (${err.getClass().getSimpleName()}); sending without them."
                            sh(label: 'license-cleanup notify', script: notifyCmd)
                        }
                    }
                }
            }
        }
        failure {
            echo 'CRITICAL FAILURE: no further revocations were attempted. See the console log and archived reports.'
        }
        unstable {
            echo 'PARTIAL FAILURE or SAFETY GATE: review the execution summary and audit CSV.'
        }
        cleanup {
            // 18. Clean up the workspace (removes .state with intermediate personal data and the virtualenv).
            cleanWs(deleteDirs: true, disableDeferredWipeout: true, notFailBuild: true)
        }
    }
}
