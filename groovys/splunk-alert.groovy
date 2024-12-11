pipeline {
    agent any

    environment {
        SPLUNK_URL = 'https://my-splunk.com:8089/servicesNS/splunk/search/saved/searches'
        GIT_REPO_URL = 'https://my-git.example.com/sigmahq'
    }

    parameters {
        string(name: 'SPL_DIRECTORY', defaultValue: 'path/to/your/dir', description: 'Path to the directory containing .spl files')
    }

    stages {
        stage('Clone Source Repo') {
            steps {
                checkout([$class: 'GitSCM', 
                    branches: [[name: '*/spl']],
                    userRemoteConfigs: [[url: env.GIT_REPO_URL, credentialsId: 'git-credential-id']]
                ])
            }
        }

        stage('Apply .spl Rules to Splunk') {
            steps {
                script {
                    def splDirectory = params.SPL_DIRECTORY
                    def splFiles = findFiles(glob: "${splDirectory}/*.spl")

                    if (splFiles.length == 0) {
                        echo "No .spl files found in the directory: ${splDirectory}"
                        currentBuild.result = 'FAILURE'
                        error("No .spl files found. Aborting.")
                    }

                    splFiles.each { file ->
                        def fileName = file.name
                        def fileContent = readFile(file.path)
                        def alertName = fileName.replaceAll('.spl$', '')

                        def alert_comparator = "equal to"
                        def alert_threshold = "0"
                        def cron = "0 6 * * 1"
                        def alert_message = "The alert condition for '\$name\$' was triggered."

                        def alertExists = false
                            try {
                                def checkResponse = httpRequest(
                                    url: "${SPLUNK_URL}/${alertName}",
                                    httpMode: 'GET',
                                    authentication: 'splunk-credential-id',
                                    validResponseCodes: '200:299',
                                    ignoreSslErrors: true
                                )

                                if (checkResponse.status == 200) {
                                    echo "Alert ${alertName} already exists. Skipping creation."
                                    alertExists = true
                                }
                            } catch (Exception e) {
                                echo "Alert ${alertName} does not exist. Proceeding with creation."
                            }

                        if (!alertExists) {
                                def headers = ["Content-Type": "application/x-www-form-urlencoded"]

                                def requestData = [
                                    "output_mode"         : "json",
                                    "action.email.to"     : EMAIL_RECIPIENT,       
                                    "action.email.sendresults": "1",
                                    "action.email.inline" : "1",
                                    "action.email.format" : "csv",
                                    "action.email.allow_empty_attachment" : "0",
                                    "action.email.message.alert": alert_message,
                                    "actions"             : "email",
                                    "alert.digest_mode"   : "1",
                                    "alert.expires"       : "24h",
                                    "alert.managedBy"     : "",
                                    "alert.severity"      : "3",
                                    "alert.suppress"      : "0",
                                    "alert.suppress.fields": "",
                                    "alert.suppress.period": "",
                                    "alert.track"         : "0",
                                    "alert_comparator"    : alert_comparator,
                                    "alert_condition"     : "",
                                    "alert_threshold"     : alert_threshold,
                                    "alert_type"          : "number of events",
                                    "allow_skew"          : "0",
                                    "cron_schedule"       : cron,
                                    "description"         : "",
                                    "disabled"            : "0",
                                    "displayview"         : "",
                                    "is_scheduled"        : "1",
                                    "is_visible"          : "1",
                                    "max_concurrent"      : "1",
                                    "name"                : alertName,
                                    "realtime_schedule"   : "1",
                                    "restart_on_searchpeer_add" : "1",
                                    "run_n_times"         : "0",
                                    "run_on_startup"      : "0",
                                    "schedule_priority"   : "default",
                                    "schedule_window"     : "0",
                                    "search"              : fileContent,
                                    "action.email"        : "1"
                                ]

                                try {
                                    def response = httpRequest(
                                        url: SPLUNK_URL,
                                        httpMode: 'POST',
                                        authentication: 'splunk-credential-id-jenkins',
                                        contentType: 'APPLICATION_FORM',
                                        customHeaders: headers.collect { key, value -> [name: key, value: value] },
                                        requestBody: requestData.collect { key, value -> "${URLEncoder.encode(key, 'UTF-8')}=${URLEncoder.encode(value.toString(), 'UTF-8')}" }.join("&"),
                                        validResponseCodes: '200:299',
                                        ignoreSslErrors: true
                                    )

                                    echo "Successfully applied alert for ${fileName}: ${response.content}"

                                    // Set ACL Permissions
                                    def aclRequestData = [
                                        "modifiable": "1",
                                        "owner": "splunk",
                                        "sharing": "global",
                                        "app": "search",
                                        "perms.read": "*",
                                        "perms.write": "admin"
                                    ]

                                    try {
                                        def aclResponse = httpRequest(
                                            url: "${SPLUNK_URL}/${alertName}/acl",
                                            httpMode: 'POST',
                                            authentication: 'splunk-credential-id',
                                            contentType: 'APPLICATION_FORM',
                                            customHeaders: headers.collect { key, value -> [name: key, value: value] },
                                            requestBody: aclRequestData.collect { key, value -> "${URLEncoder.encode(key, 'UTF-8')}=${URLEncoder.encode(value.toString(), 'UTF-8')}" }.join("&"),
                                            validResponseCodes: '200:299',
                                            ignoreSslErrors: true
                                        )

                                        echo "Successfully updated permissions for ${fileName}: ${aclResponse.content}"
                                    } catch (Exception aclException) {
                                        echo "Failed to set permissions for ${fileName}: ${aclException.message}"
                                        currentBuild.result = 'FAILURE'
                                        error("ACL update failed for alert: ${alertName}")
                                    }
                                } catch (Exception e) {
                                    echo "Failed to apply alert for ${fileName}: ${e.message}"
                                    currentBuild.result = 'FAILURE'
                                    error("Alert creation failed for ${alertName}")
                                }
                        }
                    }
                }
            }
        }
    }

    post {
        success {
            echo 'Process completed successfully'
        }
        failure {
            echo 'Build failed due to an error in the pipeline'
        }
        always {
            echo 'Pipeline execution completed'
        }
    }
}
