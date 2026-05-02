import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as yaml from 'yaml';

// ─── CloudFormation Template Validation ─────────────────────────────────────

describe('CloudFormation Template - SharedServices ECR', () => {
  const templatePath = path.resolve(__dirname, '../deploy/cloudformation/ac3-customer-cross-account-role.yaml');
  let template: any;

  it('should parse the CloudFormation template', () => {
    const raw = fs.readFileSync(templatePath, 'utf-8');
    template = yaml.parse(raw);
    expect(template).toBeDefined();
    expect(template.AWSTemplateFormatVersion).toBe('2010-09-09');
  });

  it('should have all required parameters', () => {
    const raw = fs.readFileSync(templatePath, 'utf-8');
    template = yaml.parse(raw);
    const params = Object.keys(template.Parameters || {});
    expect(params).toContain('ExternalId');
    expect(params).toContain('AC3AccountId');
  });

  it('should create an IAM role resource', () => {
    const raw = fs.readFileSync(templatePath, 'utf-8');
    template = yaml.parse(raw);
    const resources = template.Resources || {};
    const roleKeys = Object.keys(resources).filter(k =>
      resources[k].Type === 'AWS::IAM::Role'
    );
    expect(roleKeys.length).toBeGreaterThan(0);
  });
});

// ─── ECS Task Definition Validation ─────────────────────────────────────────

describe('ECS Task Definitions - SharedServices ECR', () => {
  const appTaskDefPath = path.resolve(__dirname, '../deploy/ecs/task-definition-app.json');
  const c2TaskDefPath = path.resolve(__dirname, '../deploy/ecs/task-definition-c2-worker.json');

  it('should parse the app task definition', () => {
    const raw = fs.readFileSync(appTaskDefPath, 'utf-8');
    const taskDef = JSON.parse(raw);
    expect(taskDef).toBeDefined();
    expect(taskDef.containerDefinitions).toBeDefined();
    expect(taskDef.containerDefinitions.length).toBeGreaterThan(0);
  });

  it('app task definition should reference SharedServices ECR account', () => {
    const raw = fs.readFileSync(appTaskDefPath, 'utf-8');
    const taskDef = JSON.parse(raw);
    const image = taskDef.containerDefinitions[0].image;
    expect(image).toContain('890319879326');
    expect(image).toContain('ace-c3/caldera-dashboard');
  });

  it('app task definition should have correct role names', () => {
    const raw = fs.readFileSync(appTaskDefPath, 'utf-8');
    const taskDef = JSON.parse(raw);
    expect(taskDef.executionRoleArn).toContain('ac3-dev-ecs-execution-role');
    expect(taskDef.taskRoleArn).toContain('ac3-dev-app-task-role');
  });

  it('should parse the C2 worker task definition', () => {
    const raw = fs.readFileSync(c2TaskDefPath, 'utf-8');
    const taskDef = JSON.parse(raw);
    expect(taskDef).toBeDefined();
    expect(taskDef.containerDefinitions).toBeDefined();
  });

  it('C2 worker task definition should reference SharedServices ECR account', () => {
    const raw = fs.readFileSync(c2TaskDefPath, 'utf-8');
    const taskDef = JSON.parse(raw);
    const image = taskDef.containerDefinitions[0].image;
    expect(image).toContain('890319879326');
  });

  it('C2 worker should have the correct task role', () => {
    const raw = fs.readFileSync(c2TaskDefPath, 'utf-8');
    const taskDef = JSON.parse(raw);
    expect(taskDef.taskRoleArn).toContain('ac3-dev-c2-task-role');
  });
});

// ─── Buildspec Validation ───────────────────────────────────────────────────

describe('CodeBuild Buildspec', () => {
  const buildspecPath = path.resolve(__dirname, '../buildspec.yml');

  it('should parse the buildspec', () => {
    const raw = fs.readFileSync(buildspecPath, 'utf-8');
    const spec = yaml.parse(raw);
    expect(spec).toBeDefined();
    expect(spec.version).toBeDefined();
  });

  it('should have pre_build, build, and post_build phases', () => {
    const raw = fs.readFileSync(buildspecPath, 'utf-8');
    const spec = yaml.parse(raw);
    expect(spec.phases).toBeDefined();
    expect(spec.phases.pre_build).toBeDefined();
    expect(spec.phases.build).toBeDefined();
    expect(spec.phases.post_build).toBeDefined();
  });

  it('should reference SharedServices ECR account in pre_build login', () => {
    const raw = fs.readFileSync(buildspecPath, 'utf-8');
    // Check that the buildspec contains cross-account ECR login
    expect(raw).toContain('890319879326');
  });
});

// ─── Deploy Script Validation ───────────────────────────────────────────────

describe('Deploy Script', () => {
  const deployPath = path.resolve(__dirname, '../deploy/ecs/deploy.sh');

  it('should exist and be readable', () => {
    expect(fs.existsSync(deployPath)).toBe(true);
    const raw = fs.readFileSync(deployPath, 'utf-8');
    expect(raw.length).toBeGreaterThan(0);
  });

  it('should reference SharedServices ECR account', () => {
    const raw = fs.readFileSync(deployPath, 'utf-8');
    expect(raw).toContain('890319879326');
  });

  it('should have executable shebang', () => {
    const raw = fs.readFileSync(deployPath, 'utf-8');
    expect(raw.startsWith('#!/')).toBe(true);
  });
});

// ─── Vendor Risk Score Computation ──────────────────────────────────────────

describe('Vendor Risk Score Computation', () => {
  // Test the scoring algorithm used in getVendorRiskHistory
  function computeVendorRiskScore(cves: { severity: string; kevListed?: boolean }[]) {
    let critical = 0, high = 0, medium = 0, low = 0, kev = 0;
    for (const cve of cves) {
      if (cve.severity === 'critical') critical++;
      else if (cve.severity === 'high') high++;
      else if (cve.severity === 'medium') medium++;
      else low++;
      if (cve.kevListed) kev++;
    }
    const total = cves.length;
    if (total === 0) return { score: 0, band: 'MINIMAL' };
    const score = Math.min(100, Math.round(
      (critical * 25 + high * 15 + medium * 8 + low * 3 + kev * 10) /
      Math.max(1, total) * 10
    ));
    const band = score >= 80 ? 'CRITICAL' : score >= 60 ? 'HIGH' : score >= 40 ? 'MEDIUM' : score >= 20 ? 'LOW' : 'MINIMAL';
    return { score, band };
  }

  it('should return MINIMAL for no CVEs', () => {
    const result = computeVendorRiskScore([]);
    expect(result.score).toBe(0);
    expect(result.band).toBe('MINIMAL');
  });

  it('should score all-critical CVEs as CRITICAL', () => {
    const result = computeVendorRiskScore([
      { severity: 'critical' },
      { severity: 'critical' },
      { severity: 'critical' },
    ]);
    expect(result.score).toBeGreaterThanOrEqual(80);
    expect(result.band).toBe('CRITICAL');
  });

  it('should score KEV-listed CVEs higher', () => {
    const withoutKev = computeVendorRiskScore([
      { severity: 'medium' },
      { severity: 'medium' },
      { severity: 'medium' },
      { severity: 'low' },
    ]);
    const withKev = computeVendorRiskScore([
      { severity: 'medium', kevListed: true },
      { severity: 'medium', kevListed: true },
      { severity: 'medium', kevListed: true },
      { severity: 'low', kevListed: true },
    ]);
    expect(withKev.score).toBeGreaterThan(withoutKev.score);
  });

  it('should score low-severity CVEs as LOW or MINIMAL', () => {
    const result = computeVendorRiskScore([
      { severity: 'low' },
      { severity: 'low' },
      { severity: 'low' },
    ]);
    expect(result.score).toBeLessThan(40);
    expect(['LOW', 'MINIMAL']).toContain(result.band);
  });

  it('should cap at 100', () => {
    const manyCritical = Array(20).fill({ severity: 'critical', kevListed: true });
    const result = computeVendorRiskScore(manyCritical);
    expect(result.score).toBeLessThanOrEqual(100);
  });
});

// ─── Trend Computation ──────────────────────────────────────────────────────

describe('Vendor Risk Trend Computation', () => {
  function computeTrend(currentScore: number, previousScore: number) {
    const delta = currentScore - previousScore;
    let trend: 'improving' | 'worsening' | 'stable' = 'stable';
    if (delta >= 5) trend = 'worsening';
    else if (delta <= -5) trend = 'improving';
    return { trend, delta };
  }

  it('should detect improving trend when score drops by 5+', () => {
    const result = computeTrend(30, 40);
    expect(result.trend).toBe('improving');
    expect(result.delta).toBe(-10);
  });

  it('should detect worsening trend when score rises by 5+', () => {
    const result = computeTrend(50, 40);
    expect(result.trend).toBe('worsening');
    expect(result.delta).toBe(10);
  });

  it('should detect stable trend when delta is within 5', () => {
    const result = computeTrend(42, 40);
    expect(result.trend).toBe('stable');
    expect(result.delta).toBe(2);
  });

  it('should detect stable at exactly +4', () => {
    const result = computeTrend(44, 40);
    expect(result.trend).toBe('stable');
  });

  it('should detect worsening at exactly +5', () => {
    const result = computeTrend(45, 40);
    expect(result.trend).toBe('worsening');
  });

  it('should detect improving at exactly -5', () => {
    const result = computeTrend(35, 40);
    expect(result.trend).toBe('improving');
  });
});

// ─── IAM Execution Role Policy ──────────────────────────────────────────────

describe('IAM Execution Role Policy', () => {
  const policyPath = path.resolve(__dirname, '../deploy/ecs/iam-execution-role-policy.json');

  it('should exist and parse', () => {
    const raw = fs.readFileSync(policyPath, 'utf-8');
    const policy = JSON.parse(raw);
    expect(policy).toBeDefined();
    expect(policy.Version).toBe('2012-10-17');
  });

  it('should scope ECR pull to SharedServices account', () => {
    const raw = fs.readFileSync(policyPath, 'utf-8');
    expect(raw).toContain('890319879326');
  });

  it('should include ECR pull actions', () => {
    const raw = fs.readFileSync(policyPath, 'utf-8');
    const policy = JSON.parse(raw);
    const allActions = policy.Statement.flatMap((s: any) => 
      Array.isArray(s.Action) ? s.Action : [s.Action]
    );
    expect(allActions).toContain('ecr:GetDownloadUrlForLayer');
    expect(allActions).toContain('ecr:BatchGetImage');
  });
});
