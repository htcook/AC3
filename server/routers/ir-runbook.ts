/**
 * Incident Response Runbook Router
 *
 * tRPC procedures for managing IR runbook entries that map CloudWatch alarm
 * triggers to response procedures and escalation paths.
 */
import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import {
  createIrRunbookEntry,
  listIrRunbookEntries,
  getIrRunbookEntry,
  updateIrRunbookEntry,
  deleteIrRunbookEntry,
  searchIrRunbook,
  incrementIrRunbookTriggerCount,
} from "../db";
import { randomUUID } from "crypto";

const responseStepSchema = z.object({
  order: z.number(),
  title: z.string(),
  description: z.string(),
  command: z.string().optional(),
  automated: z.boolean(),
  estimatedMinutes: z.number(),
});

const escalationPathSchema = z.object({
  level: z.number(),
  role: z.string(),
  contactMethod: z.string(),
  timeoutMinutes: z.number(),
  description: z.string(),
});

export const irRunbookRouter = router({
  /** Create a new runbook entry */
  create: protectedProcedure
    .input(z.object({
      alarmName: z.string().min(1),
      alarmPattern: z.string().optional(),
      triggerDescription: z.string().min(1),
      severity: z.enum(["critical", "high", "medium", "low", "informational"]),
      category: z.enum(["infrastructure", "application", "security", "performance", "availability"]),
      responseSteps: z.array(responseStepSchema).min(1),
      escalationPath: z.array(escalationPathSchema).min(1),
      relatedAlarms: z.array(z.string()).optional(),
      mitigationActions: z.array(z.string()).optional(),
      preventionMeasures: z.array(z.string()).optional(),
      owner: z.string().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const entryId = `irr-${randomUUID().slice(0, 8)}`;
      const id = await createIrRunbookEntry({
        entryId,
        alarmName: input.alarmName,
        alarmPattern: input.alarmPattern ?? null,
        triggerDescription: input.triggerDescription,
        severity: input.severity,
        category: input.category,
        responseSteps: input.responseSteps,
        escalationPath: input.escalationPath,
        relatedAlarms: input.relatedAlarms ?? null,
        mitigationActions: input.mitigationActions ?? null,
        preventionMeasures: input.preventionMeasures ?? null,
        owner: input.owner ?? null,
        createdBy: ctx.user.id,
      });
      return { id, entryId };
    }),

  /** List runbook entries with optional filters */
  list: protectedProcedure
    .input(z.object({
      severity: z.enum(["critical", "high", "medium", "low", "informational"]).optional(),
      category: z.enum(["infrastructure", "application", "security", "performance", "availability"]).optional(),
      activeOnly: z.boolean().optional(),
    }).optional())
    .query(async ({ input }) => {
      return listIrRunbookEntries({
        severity: input?.severity,
        category: input?.category,
        activeOnly: input?.activeOnly,
      });
    }),

  /** Get a single runbook entry */
  get: protectedProcedure
    .input(z.object({ entryId: z.string() }))
    .query(async ({ input }) => {
      return getIrRunbookEntry(input.entryId);
    }),

  /** Update a runbook entry */
  update: protectedProcedure
    .input(z.object({
      entryId: z.string(),
      alarmName: z.string().optional(),
      alarmPattern: z.string().optional(),
      triggerDescription: z.string().optional(),
      severity: z.enum(["critical", "high", "medium", "low", "informational"]).optional(),
      category: z.enum(["infrastructure", "application", "security", "performance", "availability"]).optional(),
      responseSteps: z.array(responseStepSchema).optional(),
      escalationPath: z.array(escalationPathSchema).optional(),
      relatedAlarms: z.array(z.string()).optional(),
      mitigationActions: z.array(z.string()).optional(),
      preventionMeasures: z.array(z.string()).optional(),
      owner: z.string().optional(),
      isActive: z.number().min(0).max(1).optional(),
    }))
    .mutation(async ({ input }) => {
      const { entryId, ...data } = input;
      await updateIrRunbookEntry(entryId, data as any);
      return { success: true };
    }),

  /** Delete a runbook entry */
  delete: protectedProcedure
    .input(z.object({ entryId: z.string() }))
    .mutation(async ({ input }) => {
      await deleteIrRunbookEntry(input.entryId);
      return { success: true };
    }),

  /** Search runbook entries */
  search: protectedProcedure
    .input(z.object({ query: z.string().min(1) }))
    .query(async ({ input }) => {
      return searchIrRunbook(input.query);
    }),

  /** Record an alarm trigger against a runbook entry */
  recordTrigger: protectedProcedure
    .input(z.object({ entryId: z.string() }))
    .mutation(async ({ input }) => {
      await incrementIrRunbookTriggerCount(input.entryId);
      return { success: true };
    }),

  /** Seed default runbook entries from monitoring stack alarms */
  seedDefaults: protectedProcedure
    .mutation(async ({ ctx }) => {
      const defaults = getDefaultRunbookEntries();
      const created: string[] = [];
      for (const entry of defaults) {
        const entryId = `irr-${randomUUID().slice(0, 8)}`;
        await createIrRunbookEntry({
          ...entry,
          entryId,
          createdBy: ctx.user.id,
        });
        created.push(entryId);
      }
      return { created, count: created.length };
    }),

  /** Get severity distribution summary */
  severitySummary: protectedProcedure
    .query(async () => {
      const entries = await listIrRunbookEntries({ activeOnly: true });
      const summary = {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        informational: 0,
        total: entries.length,
      };
      for (const e of entries) {
        if (e.severity in summary) {
          (summary as any)[e.severity]++;
        }
      }
      return summary;
    }),
});

/** Pre-built runbook entries matching the CloudWatch monitoring stack alarms */
function getDefaultRunbookEntries() {
  return [
    {
      alarmName: "ECS CPU High",
      alarmPattern: "*-ecs-cpu-high",
      triggerDescription: "ECS service CPU utilization has exceeded the configured threshold, indicating potential resource exhaustion or runaway processes.",
      severity: "high" as const,
      category: "infrastructure" as const,
      responseSteps: [
        { order: 1, title: "Check ECS Service Metrics", description: "Open CloudWatch console and review CPU utilization graph for the past hour", command: "aws cloudwatch get-metric-statistics --namespace AWS/ECS --metric-name CPUUtilization --dimensions Name=ClusterName,Value=$CLUSTER Name=ServiceName,Value=$SERVICE --start-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%S) --end-time $(date -u +%Y-%m-%dT%H:%M:%S) --period 300 --statistics Average", automated: false, estimatedMinutes: 5 },
        { order: 2, title: "Identify Hot Containers", description: "List running tasks and check individual container CPU usage", command: "aws ecs list-tasks --cluster $CLUSTER --service-name $SERVICE", automated: false, estimatedMinutes: 5 },
        { order: 3, title: "Check for Runaway Processes", description: "Exec into the container and check top processes", command: "aws ecs execute-command --cluster $CLUSTER --task $TASK_ID --container app --interactive --command 'top -b -n 1'", automated: false, estimatedMinutes: 10 },
        { order: 4, title: "Scale Service if Needed", description: "Increase desired count to distribute load", command: "aws ecs update-service --cluster $CLUSTER --service $SERVICE --desired-count $NEW_COUNT", automated: false, estimatedMinutes: 5 },
      ],
      escalationPath: [
        { level: 1, role: "On-Call Engineer", contactMethod: "Slack #ops-alerts", timeoutMinutes: 15, description: "Initial triage and assessment" },
        { level: 2, role: "Platform Lead", contactMethod: "Phone", timeoutMinutes: 30, description: "Scaling decision and resource allocation" },
        { level: 3, role: "CTO", contactMethod: "Phone + Email", timeoutMinutes: 60, description: "Infrastructure budget approval for emergency scaling" },
      ],
      relatedAlarms: ["ECS Memory High", "ALB Response Time"],
      mitigationActions: ["Scale ECS desired count", "Restart unhealthy tasks", "Enable auto-scaling policy"],
      preventionMeasures: ["Configure ECS auto-scaling", "Set resource limits on task definitions", "Implement request rate limiting"],
      owner: "Platform Engineering",
    },
    {
      alarmName: "ECS Memory High",
      alarmPattern: "*-ecs-memory-high",
      triggerDescription: "ECS service memory utilization has exceeded the configured threshold, risking OOM kills and service degradation.",
      severity: "critical" as const,
      category: "infrastructure" as const,
      responseSteps: [
        { order: 1, title: "Check Memory Metrics", description: "Review memory utilization trend in CloudWatch", command: "aws cloudwatch get-metric-statistics --namespace AWS/ECS --metric-name MemoryUtilization --dimensions Name=ClusterName,Value=$CLUSTER Name=ServiceName,Value=$SERVICE --start-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%S) --end-time $(date -u +%Y-%m-%dT%H:%M:%S) --period 300 --statistics Average,Maximum", automated: false, estimatedMinutes: 5 },
        { order: 2, title: "Check for Memory Leaks", description: "Review application logs for OOM warnings or memory allocation errors", command: "aws logs filter-log-events --log-group-name /ecs/$SERVICE --filter-pattern 'OutOfMemory OR heap OR allocation'", automated: false, estimatedMinutes: 10 },
        { order: 3, title: "Restart Tasks", description: "Force new deployment to restart all tasks with fresh memory", command: "aws ecs update-service --cluster $CLUSTER --service $SERVICE --force-new-deployment", automated: false, estimatedMinutes: 5 },
        { order: 4, title: "Increase Task Memory", description: "Update task definition with higher memory limit if persistent", command: "# Update task definition memory in terraform/cloudformation and redeploy", automated: false, estimatedMinutes: 30 },
      ],
      escalationPath: [
        { level: 1, role: "On-Call Engineer", contactMethod: "Slack #ops-alerts + PagerDuty", timeoutMinutes: 10, description: "Immediate triage — OOM risk" },
        { level: 2, role: "Platform Lead", contactMethod: "Phone", timeoutMinutes: 20, description: "Memory allocation review and task restart" },
        { level: 3, role: "CTO", contactMethod: "Phone + Email", timeoutMinutes: 45, description: "Emergency infrastructure changes" },
      ],
      relatedAlarms: ["ECS CPU High", "ECS No Running Tasks"],
      mitigationActions: ["Force new deployment", "Increase task memory limits", "Enable memory-based auto-scaling"],
      preventionMeasures: ["Set memory limits in task definitions", "Monitor memory trends weekly", "Implement graceful degradation"],
      owner: "Platform Engineering",
    },
    {
      alarmName: "ECS No Running Tasks",
      alarmPattern: "*-ecs-no-tasks",
      triggerDescription: "The ECS service has zero running tasks, meaning the application is completely down.",
      severity: "critical" as const,
      category: "availability" as const,
      responseSteps: [
        { order: 1, title: "Check Service Events", description: "Review ECS service events for deployment failures or task crashes", command: "aws ecs describe-services --cluster $CLUSTER --services $SERVICE --query 'services[0].events[:10]'", automated: false, estimatedMinutes: 5 },
        { order: 2, title: "Check Stopped Tasks", description: "Examine recently stopped tasks for error reasons", command: "aws ecs list-tasks --cluster $CLUSTER --service-name $SERVICE --desired-status STOPPED | head -5", automated: false, estimatedMinutes: 5 },
        { order: 3, title: "Force New Deployment", description: "Trigger a new deployment to restart the service", command: "aws ecs update-service --cluster $CLUSTER --service $SERVICE --force-new-deployment", automated: false, estimatedMinutes: 5 },
        { order: 4, title: "Verify Recovery", description: "Wait for tasks to reach RUNNING state and verify health checks pass", command: "aws ecs wait services-stable --cluster $CLUSTER --services $SERVICE", automated: false, estimatedMinutes: 10 },
      ],
      escalationPath: [
        { level: 1, role: "On-Call Engineer", contactMethod: "PagerDuty (P1)", timeoutMinutes: 5, description: "IMMEDIATE — Service is down" },
        { level: 2, role: "Platform Lead + App Lead", contactMethod: "Phone bridge", timeoutMinutes: 15, description: "Joint triage of infrastructure vs application issue" },
        { level: 3, role: "CTO + VP Engineering", contactMethod: "War room", timeoutMinutes: 30, description: "Full incident command" },
      ],
      relatedAlarms: ["ECS CPU High", "ECS Memory High", "ALB 5xx Errors"],
      mitigationActions: ["Force new deployment", "Rollback to previous task definition", "Check ECR image availability"],
      preventionMeasures: ["Maintain minimum 2 running tasks", "Enable circuit breaker on deployments", "Pre-pull container images"],
      owner: "Platform Engineering",
    },
    {
      alarmName: "ALB 5xx Errors",
      alarmPattern: "*-alb-5xx",
      triggerDescription: "The Application Load Balancer is returning elevated 5xx server errors, indicating backend failures.",
      severity: "high" as const,
      category: "application" as const,
      responseSteps: [
        { order: 1, title: "Check ALB Access Logs", description: "Review ALB access logs for error patterns and affected endpoints", command: "aws logs filter-log-events --log-group-name /alb/$ALB_NAME --filter-pattern '\"5\"'", automated: false, estimatedMinutes: 10 },
        { order: 2, title: "Check Target Health", description: "Verify all targets are healthy in the target group", command: "aws elbv2 describe-target-health --target-group-arn $TG_ARN", automated: false, estimatedMinutes: 5 },
        { order: 3, title: "Review Application Logs", description: "Check application logs for unhandled exceptions or crashes", command: "aws logs filter-log-events --log-group-name /ecs/$SERVICE --filter-pattern 'ERROR OR Exception OR FATAL'", automated: false, estimatedMinutes: 10 },
        { order: 4, title: "Restart Unhealthy Tasks", description: "Stop tasks that are returning errors", command: "aws ecs update-service --cluster $CLUSTER --service $SERVICE --force-new-deployment", automated: false, estimatedMinutes: 5 },
      ],
      escalationPath: [
        { level: 1, role: "On-Call Engineer", contactMethod: "Slack #ops-alerts", timeoutMinutes: 15, description: "Triage error source (ALB vs application)" },
        { level: 2, role: "App Lead", contactMethod: "Slack + Phone", timeoutMinutes: 30, description: "Application-level debugging" },
      ],
      relatedAlarms: ["ALB Response Time", "Unhealthy Hosts", "App Error Rate"],
      mitigationActions: ["Restart unhealthy tasks", "Rollback recent deployment", "Enable maintenance page"],
      preventionMeasures: ["Implement health check endpoints", "Add circuit breakers", "Canary deployments"],
      owner: "Application Engineering",
    },
    {
      alarmName: "ALB Response Time",
      alarmPattern: "*-alb-response-time",
      triggerDescription: "Average response time from the ALB has exceeded the configured threshold, indicating performance degradation.",
      severity: "medium" as const,
      category: "performance" as const,
      responseSteps: [
        { order: 1, title: "Identify Slow Endpoints", description: "Check ALB access logs to find which endpoints are slow", command: "aws logs filter-log-events --log-group-name /alb/$ALB_NAME --filter-pattern '{ $.target_processing_time > 3 }'", automated: false, estimatedMinutes: 10 },
        { order: 2, title: "Check Database Performance", description: "Review database slow query logs and connection pool status", command: "# Check RDS/TiDB performance insights", automated: false, estimatedMinutes: 15 },
        { order: 3, title: "Review Resource Utilization", description: "Check if CPU/memory constraints are causing slowdowns", command: "aws cloudwatch get-metric-statistics --namespace AWS/ECS --metric-name CPUUtilization --dimensions Name=ClusterName,Value=$CLUSTER Name=ServiceName,Value=$SERVICE --period 300 --statistics Average", automated: false, estimatedMinutes: 5 },
        { order: 4, title: "Scale if Needed", description: "Add more tasks to handle load", command: "aws ecs update-service --cluster $CLUSTER --service $SERVICE --desired-count $NEW_COUNT", automated: false, estimatedMinutes: 5 },
      ],
      escalationPath: [
        { level: 1, role: "On-Call Engineer", contactMethod: "Slack #ops-alerts", timeoutMinutes: 30, description: "Performance investigation" },
        { level: 2, role: "App Lead + DBA", contactMethod: "Slack", timeoutMinutes: 60, description: "Deep performance analysis" },
      ],
      relatedAlarms: ["ECS CPU High", "ALB 5xx Errors"],
      mitigationActions: ["Scale ECS service", "Optimize slow queries", "Enable caching"],
      preventionMeasures: ["Performance testing before releases", "Query optimization reviews", "CDN for static assets"],
      owner: "Application Engineering",
    },
    {
      alarmName: "App Error Rate",
      alarmPattern: "*-app-error-rate",
      triggerDescription: "Application-level error rate has exceeded the threshold, detected via CloudWatch log metric filters.",
      severity: "high" as const,
      category: "application" as const,
      responseSteps: [
        { order: 1, title: "Review Error Logs", description: "Check application logs for the specific errors being triggered", command: "aws logs filter-log-events --log-group-name /ecs/$SERVICE --filter-pattern 'ERROR' --start-time $(date -u -d '30 minutes ago' +%s)000", automated: false, estimatedMinutes: 10 },
        { order: 2, title: "Check Recent Deployments", description: "Verify if a recent deployment introduced the errors", command: "aws ecs describe-services --cluster $CLUSTER --services $SERVICE --query 'services[0].deployments'", automated: false, estimatedMinutes: 5 },
        { order: 3, title: "Rollback if Deployment-Related", description: "Rollback to previous task definition if errors started after deployment", command: "aws ecs update-service --cluster $CLUSTER --service $SERVICE --task-definition $PREVIOUS_TASK_DEF", automated: false, estimatedMinutes: 10 },
        { order: 4, title: "Apply Hotfix", description: "If root cause identified, apply targeted fix and redeploy", command: "# git revert or hotfix branch → CI/CD pipeline", automated: false, estimatedMinutes: 60 },
      ],
      escalationPath: [
        { level: 1, role: "On-Call Engineer", contactMethod: "Slack #ops-alerts", timeoutMinutes: 15, description: "Error triage and correlation with deployments" },
        { level: 2, role: "App Lead", contactMethod: "Slack + Phone", timeoutMinutes: 30, description: "Root cause analysis and fix decision" },
      ],
      relatedAlarms: ["ALB 5xx Errors", "Fatal Errors"],
      mitigationActions: ["Rollback deployment", "Disable feature flag", "Increase error budget temporarily"],
      preventionMeasures: ["Automated testing in CI", "Canary deployments", "Feature flags for new code paths"],
      owner: "Application Engineering",
    },
    {
      alarmName: "Fatal Errors",
      alarmPattern: "*-fatal-errors",
      triggerDescription: "A fatal error or application crash has been detected in the logs. This typically indicates an unrecoverable error.",
      severity: "critical" as const,
      category: "application" as const,
      responseSteps: [
        { order: 1, title: "Check Fatal Error Details", description: "Review the specific fatal error in application logs", command: "aws logs filter-log-events --log-group-name /ecs/$SERVICE --filter-pattern 'FATAL OR panic OR crash'", automated: false, estimatedMinutes: 5 },
        { order: 2, title: "Check Task Status", description: "Verify if tasks are restarting or stuck in crash loop", command: "aws ecs describe-tasks --cluster $CLUSTER --tasks $(aws ecs list-tasks --cluster $CLUSTER --service-name $SERVICE --query 'taskArns' --output text)", automated: false, estimatedMinutes: 5 },
        { order: 3, title: "Immediate Rollback", description: "Rollback to last known good task definition", command: "aws ecs update-service --cluster $CLUSTER --service $SERVICE --task-definition $LAST_GOOD_TASK_DEF", automated: false, estimatedMinutes: 10 },
        { order: 4, title: "Post-Incident Analysis", description: "Collect crash dumps, stack traces, and create incident report", command: "# Collect logs, create JIRA ticket, schedule post-mortem", automated: false, estimatedMinutes: 30 },
      ],
      escalationPath: [
        { level: 1, role: "On-Call Engineer", contactMethod: "PagerDuty (P1)", timeoutMinutes: 5, description: "IMMEDIATE — Application crash detected" },
        { level: 2, role: "App Lead + Platform Lead", contactMethod: "Phone bridge", timeoutMinutes: 15, description: "Joint triage and rollback decision" },
        { level: 3, role: "CTO", contactMethod: "Phone", timeoutMinutes: 30, description: "Incident command if service impact confirmed" },
      ],
      relatedAlarms: ["App Error Rate", "ECS No Running Tasks"],
      mitigationActions: ["Immediate rollback", "Disable affected feature", "Restart service"],
      preventionMeasures: ["Crash reporting integration", "Graceful error handling", "Pre-deployment smoke tests"],
      owner: "Application Engineering",
    },
    {
      alarmName: "Unhealthy Hosts",
      alarmPattern: "*-unhealthy-hosts",
      triggerDescription: "One or more targets in the ALB target group are failing health checks.",
      severity: "medium" as const,
      category: "availability" as const,
      responseSteps: [
        { order: 1, title: "Check Target Health", description: "Identify which targets are unhealthy and the failure reason", command: "aws elbv2 describe-target-health --target-group-arn $TG_ARN", automated: false, estimatedMinutes: 5 },
        { order: 2, title: "Check Health Check Endpoint", description: "Verify the health check endpoint is responding correctly", command: "curl -v http://$TARGET_IP:$PORT/health", automated: false, estimatedMinutes: 5 },
        { order: 3, title: "Review Task Logs", description: "Check logs of the unhealthy task for errors", command: "aws logs filter-log-events --log-group-name /ecs/$SERVICE --filter-pattern 'health'", automated: false, estimatedMinutes: 10 },
        { order: 4, title: "Deregister and Replace", description: "Stop unhealthy tasks and let ECS replace them", command: "aws ecs stop-task --cluster $CLUSTER --task $UNHEALTHY_TASK_ARN --reason 'Failed health checks'", automated: false, estimatedMinutes: 5 },
      ],
      escalationPath: [
        { level: 1, role: "On-Call Engineer", contactMethod: "Slack #ops-alerts", timeoutMinutes: 15, description: "Health check failure investigation" },
        { level: 2, role: "Platform Lead", contactMethod: "Slack", timeoutMinutes: 30, description: "Infrastructure-level investigation" },
      ],
      relatedAlarms: ["ECS No Running Tasks", "ALB 5xx Errors"],
      mitigationActions: ["Stop unhealthy tasks", "Force new deployment", "Check security group rules"],
      preventionMeasures: ["Robust health check endpoints", "Gradual deployment strategy", "Pre-deployment health verification"],
      owner: "Platform Engineering",
    },
  ];
}
