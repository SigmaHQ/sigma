pipeline {
    agent any

    environment {
        GIT_REPO = 'https://github.com/SigmaHQ/sigma'
        DAYS_TO_CHECK = '7'  // String, to be converted to integer
        EMAIL_RECIPIENTS = 'recipient1@example.com,recipient2@example.com'
        EMAIL_SENDER = 'sender@example.com'
    }

    stages {
        stage('Clone Repository') {
            steps {
                git branch: 'master', url: "$GIT_REPO"
            }
        }

        stage('Check for Changes') {
            steps {
                script {
                    // Convert DAYS_TO_CHECK to integer
                    def daysToCheck = DAYS_TO_CHECK.toInteger()

                    // Get the current date and subtract days
                    def currentDate = new Date()
                    def sdf = new java.text.SimpleDateFormat("yyyy-MM-dd")
                    
                    // Calculate the cutoff date
                    def calendar = Calendar.getInstance()
                    calendar.setTime(currentDate)
                    calendar.add(Calendar.DATE, -daysToCheck)  // Subtract the number of days
                    def cutoffDate = calendar.getTime()
                    def cutoffDateFormatted = sdf.format(cutoffDate)

                    // Use a more lenient format like "7 days ago"
                    def sinceOption = "${daysToCheck} days ago"

                    // Debug: Print out the date for troubleshooting
                    echo "Checking for changes since: ${sinceOption}"

                    // Run git log command with relative date format and filter for .yml files inside the rules/ directory
                    def gitLogOutput = sh(script: "git log --since='${sinceOption}' --name-only --pretty=format: -- 'rules/**/*' | grep -E '\\.yml\$' | sort | uniq", returnStdout: true).trim()
                    
                    // Debug: Output the full git log result for troubleshooting
                    echo "Git log output:\n${gitLogOutput}"

                    if (gitLogOutput) {
                        // Save the output to an environment variable for post actions
                        env.GIT_LOG_OUTPUT = gitLogOutput
                        echo "New or edited .yml files found in the 'rules/' folder:"
                        echo gitLogOutput
                    } else {
                        env.GIT_LOG_OUTPUT = ""
                        echo "No new or updated .yml files found in the 'rules/' folder."
                    }
                }
            }
        }
    }

    post {
        success {
            script {
                if (env.GIT_LOG_OUTPUT) {
                    // Send email with the list of changed files
                    emailext(
                        subject: "Jenkins Pipeline: New or Updated .yml Files Sigma Found",
                        body: """
                            <p>The following .yml files have been added or updated in the last ${DAYS_TO_CHECK} days:</p>
                            <pre>${env.GIT_LOG_OUTPUT}</pre>
                        """,
                        recipientProviders: [[$class: 'DevelopersRecipientProvider']],
                        to: "${EMAIL_RECIPIENTS}",
                        from: "${EMAIL_SENDER}",
                        mimeType: 'text/html'
                    )
                } else {
                    echo "No changes detected, email notification will not be sent."
                }
            }
        }

        failure {
            emailext(
                subject: "Jenkins Pipeline Failed",
                body: """
                    <p>The pipeline failed during execution. Please check the logs for more details.</p>
                """,
                recipientProviders: [[$class: 'CulpritsRecipientProvider']],
                to: "${EMAIL_RECIPIENTS}",
                from: "${EMAIL_SENDER}",
                mimeType: 'text/html'
            )
        }
    }
}
