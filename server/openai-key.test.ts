import { describe, it, expect } from 'vitest';

describe('OpenAI API Key Validation', () => {
  it('should have OPENAI_API_KEY set in environment', () => {
    const key = process.env.OPENAI_API_KEY;
    expect(key).toBeDefined();
    expect(key!.length).toBeGreaterThan(20);
    expect(key!.startsWith('sk-')).toBe(true);
  });

  it('should successfully call OpenAI API with the key', async () => {
    const key = process.env.OPENAI_API_KEY;
    const response = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${key}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        model: 'gpt-4o-mini',
        messages: [{ role: 'user', content: 'Say "ok"' }],
        max_tokens: 5,
      }),
    });
    expect(response.status).toBe(200);
    const data = await response.json();
    expect(data.choices).toBeDefined();
    expect(data.choices.length).toBeGreaterThan(0);
  }, 15000);
});
