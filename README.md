# Telegram Bot - Production Observability

## 🏗️ Architecture Overview

This Telegram bot is deployed on AWS with production-grade observability:
- **Lambda**: Serverless function handling bot logic
- **DynamoDB**: Stores messages, notes, and metadata
- **S3**: Stores uploaded media files
- **CloudWatch**: Structured logging, metrics, and alarms
- **SNS**: Email notifications for critical errors

---

## 📊 Observability Implementation

### 1. **Structured Logging**

All Lambda executions produce JSON-formatted structured logs with consistent fields:
```json
{
  "level": "INFO",
  "timestamp": "2025-01-23T10:15:30.123456+00:00",
  "message": "Processing text message",
  "request_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "user_id": "123456789",
  "message_id": "987654",
  "action": "handle_text",
  "outcome": "success"
}
```

**Error logs include additional fields:**
```json
{
  "level": "ERROR",
  "error_type": "ClientError",
  "error_message": "DynamoDB connection failed",
  "stack_trace": "Traceback (most recent call last)...",
  "outcome": "failure"
}
```

**Key Fields:**
- `level`: Log severity (INFO, WARNING, ERROR, DEBUG)
- `timestamp`: ISO 8601 format with timezone
- `request_id`: AWS Lambda request identifier
- `user_id`: Telegram user/chat ID
- `message_id`: Telegram message identifier
- `action`: Specific operation (e.g., "handle_photo", "save", "newnote")
- `outcome`: Result status ("success", "failure", "skipped")
- `error_type`, `error_message`, `stack_trace`: Present on errors only

---

### 2. **Log Retention Policy**

| Log Group | Retention | Purpose |
|-----------|-----------|---------|
| `/aws/lambda/telegram-bot-lambda-v2` | 14 days | Lambda execution logs |
| `/aws/apigateway/telegram-http-api-v2` | 7 days | API Gateway access logs |

**Rationale:**
- Lambda logs retained longer for debugging and audit trails
- API Gateway logs retained shorter (less detailed, higher volume)
- Saves costs while maintaining adequate history

---

### 3. **Metric Filters**

#### Error Detection
```
Pattern: { $.level = "ERROR" }
Metric: TelegramBot/Lambda/LambdaErrorCount
```
Captures any log entry with `level` field set to `ERROR`.

#### Success Tracking
```
Pattern: { $.level = "INFO" && $.outcome = "success" }
Metric: TelegramBot/Lambda/LambdaSuccessCount
```
Tracks successful operations for health monitoring.

#### Message Processing
```
Pattern: { $.message = "Message saved to DynamoDB" }
Metric: TelegramBot/Lambda/MessagesProcessed
```
Counts messages successfully persisted.

#### File Uploads
```
Pattern: { $.message = "File uploaded to S3" }
Metric: TelegramBot/Lambda/FilesUploaded
```
Tracks media file uploads.

---

### 4. **CloudWatch Alarms**

#### Primary Error Alarm
- **Name**: `telegram-bot-lambda-errors`
- **Condition**: `LambdaErrorCount ≥ 1` within 5 minutes
- **Action**: Send SNS notification
- **Purpose**: Immediate alert on any error

#### High Error Rate Alarm
- **Name**: `telegram-bot-lambda-high-error-rate`
- **Condition**: `LambdaErrorCount ≥ 5` within 5 minutes
- **Severity**: Critical
- **Purpose**: Detect systemic failures

#### Performance Alarm
- **Name**: `telegram-bot-lambda-duration`
- **Condition**: Average duration > 30 seconds for 2 consecutive periods
- **Purpose**: Detect performance degradation

#### Throttling Alarm
- **Name**: `telegram-bot-lambda-throttles`
- **Condition**: Any throttles detected
- **Purpose**: Alert on Lambda concurrency limits

---

### 5. **Viewing Logs and Alarms**

#### CloudWatch Logs
1. AWS Console → **CloudWatch** → **Log groups**
2. Select `/aws/lambda/telegram-bot-lambda-v2`
3. Click latest log stream to view real-time logs
4. Use **CloudWatch Insights** for advanced queries:
```sql
fields @timestamp, level, message, user_id, action, outcome
| filter level = "ERROR"
| sort @timestamp desc
| limit 20
```

#### Metrics and Alarms
1. AWS Console → **CloudWatch** → **Alarms**
2. View alarm status (OK, In alarm, Insufficient data)
3. Click alarm name for detailed history and graph

#### Dashboard
1. AWS Console → **CloudWatch** → **Dashboards**
2. Select `telegram-bot-observability`
3. View real-time metrics: errors, success rate, duration, recent errors

**Direct link** (after deployment):
```
terraform output dashboard_url
```

#### Email Notifications
- Configure email addresses in `terraform.tfvars`:
```hcl
  alarm_emails = ["your.email@example.com"]
```
- Confirm SNS subscription via email
- Receive alerts when alarms trigger and recover

---

## 🧪 Testing & Verification

### Trigger Success Events
```
/start
/hello
/save mykey myvalue
/echo Hello World
```
Expected: Structured INFO logs with `outcome: success`

### Trigger Test Error
```
/testerror
```
Expected:
- ERROR log with full stack trace
- Alarm transitions to "In alarm" within 5 minutes
- Email notification received
- Alarm returns to "OK" after ~10 minutes

### View Metrics
1. CloudWatch → Metrics → `TelegramBot/Lambda`
2. Check graphs for:
   - `LambdaErrorCount` (should show spike after `/testerror`)
   - `LambdaSuccessCount` (increases with each command)
   - `MessagesProcessed` (counts all text messages)

---

## 📸 Evidence

### 1. Structured Logs
![Structured Logs](./evidence-1-structured-logs.png)
*CloudWatch log stream showing JSON-formatted logs with consistent fields*

### 2. Error Logs with Stack Trace
![Error Logs](./evidence-2-error-logs.png)
*ERROR-level log entry triggered by `/testerror` command*

### 3. Metric Filter Statistics
![Metric Filter](./evidence-3-metric-filter-stats.png)
*CloudWatch metrics showing error count over time*

### 4. Alarm in ALARM State
![Alarm Triggered](./evidence-4-alarm-in-alarm-state.png)
*Error alarm triggered after detecting test error*

### 5. Alarm Returned to OK
![Alarm Recovered](./evidence-5-alarm-returned-to-ok.png)
*Alarm automatically recovered after error condition cleared*

### 6. CloudWatch Dashboard (Bonus)
![Dashboard](./evidence-6-dashboard.png)
*Complete observability dashboard with all metrics*

---

## 🚀 Deployment Instructions

### Prerequisites
- AWS CLI configured with appropriate credentials
- Terraform >= 1.7.0
- Telegram bot token from @BotFather

### Deploy
```bash
# 1. Configure variables
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your values

# 2. Initialize Terraform
terraform init

# 3. Deploy infrastructure
terraform apply

# 4. Set Telegram webhook
WEBHOOK_URL=$(terraform output -raw webhook_url)
curl "https://api.telegram.org/bot<YOUR_TOKEN>/setWebhook?url=$WEBHOOK_URL"

# 5. Confirm SNS email subscription (check your inbox)
```

### Verify Deployment
```bash
# Check webhook status
curl "https://api.telegram.org/bot<YOUR_TOKEN>/getWebhookInfo"

# View outputs
terraform output

# Test bot in Telegram
# Send: /start
```

---

## 🔍 Troubleshooting

### Logs Not Appearing
- Check Lambda execution role has CloudWatch Logs permissions
- Verify log group exists: `aws logs describe-log-groups`

### Alarms Not Triggering
- Confirm metric filter is creating data points
- Check alarm evaluation period (5 minutes)
- Verify SNS subscription is confirmed

### Email Notifications Not Received
- Check spam folder
- Confirm SNS subscription via email link
- Verify email in `terraform.tfvars` is correct

---

## 📈 Monitoring Best Practices

1. **Regular Reviews**: Check dashboard weekly for trends
2. **Alarm Tuning**: Adjust thresholds based on actual usage patterns
3. **Cost Optimization**: Review log retention periods quarterly
4. **Incident Response**: Document error patterns and resolutions
5. **Capacity Planning**: Monitor duration and throttle metrics

---

## 🛠️ Useful Commands
```bash
# View recent logs
aws logs tail /aws/lambda/telegram-bot-lambda-v2 --follow

# Query errors from last hour
aws logs filter-log-events \
  --log-group-name /aws/lambda/telegram-bot-lambda-v2 \
  --filter-pattern '{ $.level = "ERROR" }' \
  --start-time $(date -d '1 hour ago' +%s)000

# Check alarm state
aws cloudwatch describe-alarms \
  --alarm-names telegram-bot-lambda-errors

# List metrics
aws cloudwatch list-metrics \
  --namespace TelegramBot/Lambda
```

---

## 📚 Additional Resources

- [AWS CloudWatch Documentation](https://docs.aws.amazon.com/cloudwatch/)
- [CloudWatch Logs Insights Query Syntax](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CWL_QuerySyntax.html)
- [Lambda Monitoring Best Practices](https://docs.aws.amazon.com/lambda/latest/dg/lambda-monitoring.html)
- [Telegram Bot API](https://core.telegram.org/bots/api)

---

## 📞 Support

For issues or questions:
1. Check CloudWatch logs for error details
2. Review alarm history for patterns
3. Consult metric dashboards for performance insights
4. [Open an issue](https://github.com/yourusername/your-repo/issues) with:
   - Error logs (sanitized)
   - Alarm screenshots
   - Steps to reproduce

---

## ✅ Verification Checklist

- [x] Structured logging implemented with consistent fields
- [x] CloudWatch log groups created with retention policies
- [x] Metric filters capturing errors and success events
- [x] CloudWatch alarms configured with SNS notifications
- [x] Dashboard created with key metrics
- [x] Error triggered and captured successfully
- [x] Alarm transitioned to ALARM state
- [x] Alarm recovered to OK state
- [x] Evidence screenshots collected
- [x] Documentation completed
