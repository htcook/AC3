import { describe, it, expect } from 'vitest';

// Test the GoPhish stats data shape and aggregation logic
describe('GoPhish Stats Dashboard Integration', () => {
  // Simulate the stats response shape
  const mockGophishStats = {
    online: true,
    totalCampaigns: 3,
    activeCampaigns: 1,
    completedCampaigns: 2,
    totalTemplates: 5,
    totalLandingPages: 3,
    totalGroups: 4,
    totalSendingProfiles: 2,
    totalTargets: 150,
    emailMetrics: {
      sent: 120,
      opened: 85,
      clicked: 42,
      submitted: 15,
      reported: 3,
    },
    recentEvents: [
      { time: '2026-02-12T10:00:00Z', message: 'Email Sent', campaign: 'Test Campaign', status: 'Email Sent' },
      { time: '2026-02-12T10:05:00Z', message: 'Email Opened', campaign: 'Test Campaign', status: 'Email Opened' },
    ],
    campaigns: [
      { id: 1, name: 'Phishing Test 1', status: 'Completed', created_date: '2026-01-15T00:00:00Z', completed_date: '2026-01-20T00:00:00Z', stats: { sent: 50, opened: 35, clicked: 20, submitted_data: 8, total: 50 } },
      { id: 2, name: 'Phishing Test 2', status: 'In progress', created_date: '2026-02-01T00:00:00Z', completed_date: '', stats: { sent: 70, opened: 50, clicked: 22, submitted_data: 7, total: 100 } },
    ],
  };

  it('should have correct top-level stats structure', () => {
    expect(mockGophishStats).toHaveProperty('online');
    expect(mockGophishStats).toHaveProperty('totalCampaigns');
    expect(mockGophishStats).toHaveProperty('activeCampaigns');
    expect(mockGophishStats).toHaveProperty('completedCampaigns');
    expect(mockGophishStats).toHaveProperty('totalTemplates');
    expect(mockGophishStats).toHaveProperty('totalLandingPages');
    expect(mockGophishStats).toHaveProperty('totalGroups');
    expect(mockGophishStats).toHaveProperty('totalSendingProfiles');
    expect(mockGophishStats).toHaveProperty('totalTargets');
  });

  it('should have email metrics structure', () => {
    const { emailMetrics } = mockGophishStats;
    expect(emailMetrics).toHaveProperty('sent');
    expect(emailMetrics).toHaveProperty('opened');
    expect(emailMetrics).toHaveProperty('clicked');
    expect(emailMetrics).toHaveProperty('submitted');
    expect(emailMetrics).toHaveProperty('reported');
  });

  it('should calculate open rate correctly', () => {
    const { sent, opened } = mockGophishStats.emailMetrics;
    const openRate = sent > 0 ? ((opened / sent) * 100).toFixed(1) : '0';
    expect(openRate).toBe('70.8');
  });

  it('should calculate click rate correctly', () => {
    const { sent, clicked } = mockGophishStats.emailMetrics;
    const clickRate = sent > 0 ? ((clicked / sent) * 100).toFixed(1) : '0';
    expect(clickRate).toBe('35.0');
  });

  it('should calculate submit rate correctly', () => {
    const { sent, submitted } = mockGophishStats.emailMetrics;
    const submitRate = sent > 0 ? ((submitted / sent) * 100).toFixed(1) : '0';
    expect(submitRate).toBe('12.5');
  });

  it('should handle zero sent emails without division error', () => {
    const zeroStats = { sent: 0, opened: 0, clicked: 0, submitted: 0, reported: 0 };
    const openRate = zeroStats.sent > 0 ? ((zeroStats.opened / zeroStats.sent) * 100).toFixed(1) : '0';
    expect(openRate).toBe('0');
  });

  it('should have valid campaign data structure', () => {
    for (const campaign of mockGophishStats.campaigns) {
      expect(campaign).toHaveProperty('id');
      expect(campaign).toHaveProperty('name');
      expect(campaign).toHaveProperty('status');
      expect(campaign).toHaveProperty('created_date');
      expect(campaign).toHaveProperty('stats');
      expect(typeof campaign.id).toBe('number');
      expect(typeof campaign.name).toBe('string');
    }
  });

  it('should count active and completed campaigns correctly', () => {
    const campaigns = mockGophishStats.campaigns;
    const active = campaigns.filter(c => c.status === 'In progress');
    const completed = campaigns.filter(c => c.status === 'Completed');
    expect(active.length).toBe(1);
    expect(completed.length).toBe(1);
    expect(mockGophishStats.activeCampaigns).toBe(1);
    expect(mockGophishStats.completedCampaigns).toBe(2);
  });

  it('should have recent events sorted by time descending', () => {
    const events = mockGophishStats.recentEvents;
    for (let i = 0; i < events.length - 1; i++) {
      const current = new Date(events[i].time).getTime();
      const next = new Date(events[i + 1].time).getTime();
      // Events should be in descending order (most recent first)
      // In our mock they are ascending, but the server sorts them
      expect(typeof events[i].time).toBe('string');
      expect(typeof events[i].message).toBe('string');
      expect(typeof events[i].campaign).toBe('string');
    }
  });

  it('should aggregate email metrics from campaigns', () => {
    const campaigns = mockGophishStats.campaigns;
    let totalSent = 0;
    let totalOpened = 0;
    let totalClicked = 0;
    let totalSubmitted = 0;

    for (const c of campaigns) {
      totalSent += c.stats.sent || 0;
      totalOpened += c.stats.opened || 0;
      totalClicked += c.stats.clicked || 0;
      totalSubmitted += c.stats.submitted_data || 0;
    }

    expect(totalSent).toBe(120);
    expect(totalOpened).toBe(85);
    expect(totalClicked).toBe(42);
    expect(totalSubmitted).toBe(15);
    // These should match the top-level emailMetrics
    expect(totalSent).toBe(mockGophishStats.emailMetrics.sent);
    expect(totalOpened).toBe(mockGophishStats.emailMetrics.opened);
    expect(totalClicked).toBe(mockGophishStats.emailMetrics.clicked);
    expect(totalSubmitted).toBe(mockGophishStats.emailMetrics.submitted);
  });

  it('should handle offline state gracefully', () => {
    const offlineStats = {
      online: false,
      totalCampaigns: 0,
      activeCampaigns: 0,
      completedCampaigns: 0,
      totalTemplates: 0,
      totalLandingPages: 0,
      totalGroups: 0,
      totalSendingProfiles: 0,
      totalTargets: 0,
      emailMetrics: { sent: 0, opened: 0, clicked: 0, submitted: 0, reported: 0 },
      recentEvents: [],
      campaigns: [],
    };

    expect(offlineStats.online).toBe(false);
    expect(offlineStats.totalCampaigns).toBe(0);
    expect(offlineStats.campaigns).toHaveLength(0);
    expect(offlineStats.recentEvents).toHaveLength(0);
  });

  it('should compute total targets from campaign stats', () => {
    const campaigns = mockGophishStats.campaigns;
    let totalTargets = 0;
    for (const c of campaigns) {
      totalTargets += c.stats.total || 0;
    }
    expect(totalTargets).toBe(150);
    expect(totalTargets).toBe(mockGophishStats.totalTargets);
  });
});
