import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// Mock fetch globally before importing the module
const mockFetch = vi.fn();
vi.stubGlobal("fetch", mockFetch);

// Mock ENV
vi.mock("./_core/env", () => ({
  ENV: {
    forgeApiUrl: "https://forge.test.example.com",
    forgeApiKey: "test-api-key-12345",
  },
}));

describe("LLM Retry Logic", () => {
  beforeEach(() => {
    mockFetch.mockReset();
    vi.useFakeTimers({ shouldAdvanceTime: true });
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("should succeed on first attempt when API returns 200", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        id: "test-1",
        created: Date.now(),
        model: "gemini-2.5-flash",
        choices: [{ index: 0, message: { role: "assistant", content: "Hello" }, finish_reason: "stop" }],
      }),
    });

    const { invokeLLM } = await import("./_core/llm");
    const result = await invokeLLM({
      messages: [{ role: "user", content: "test" }],
    });

    expect(result.choices[0].message.content).toBe("Hello");
    expect(mockFetch).toHaveBeenCalledTimes(1);
  });

  it("should retry on 403 and succeed on second attempt", async () => {
    // First call: 403 Forbidden
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 403,
      statusText: "Forbidden",
      text: async () => "Rate limited",
    });
    // Second call: 200 OK
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        id: "test-2",
        created: Date.now(),
        model: "gemini-2.5-flash",
        choices: [{ index: 0, message: { role: "assistant", content: "Recovered" }, finish_reason: "stop" }],
      }),
    });

    const { invokeLLM } = await import("./_core/llm");
    const result = await invokeLLM({
      messages: [{ role: "user", content: "test" }],
    });

    expect(result.choices[0].message.content).toBe("Recovered");
    expect(mockFetch).toHaveBeenCalledTimes(2);
  });

  it("should retry on 429 (rate limit) and succeed", async () => {
    // First call: 429 Too Many Requests
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 429,
      statusText: "Too Many Requests",
      text: async () => "Rate limit exceeded",
    });
    // Second call: 200 OK
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        id: "test-3",
        created: Date.now(),
        model: "gemini-2.5-flash",
        choices: [{ index: 0, message: { role: "assistant", content: "OK" }, finish_reason: "stop" }],
      }),
    });

    const { invokeLLM } = await import("./_core/llm");
    const result = await invokeLLM({
      messages: [{ role: "user", content: "test" }],
    });

    expect(result.choices[0].message.content).toBe("OK");
    expect(mockFetch).toHaveBeenCalledTimes(2);
  });

  it("should retry on 500/502/503/504 server errors", async () => {
    // First call: 502 Bad Gateway
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 502,
      statusText: "Bad Gateway",
      text: async () => "upstream error",
    });
    // Second call: 503 Service Unavailable
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 503,
      statusText: "Service Unavailable",
      text: async () => "maintenance",
    });
    // Third call: 200 OK
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        id: "test-4",
        created: Date.now(),
        model: "gemini-2.5-flash",
        choices: [{ index: 0, message: { role: "assistant", content: "Finally" }, finish_reason: "stop" }],
      }),
    });

    const { invokeLLM } = await import("./_core/llm");
    const result = await invokeLLM({
      messages: [{ role: "user", content: "test" }],
    });

    expect(result.choices[0].message.content).toBe("Finally");
    expect(mockFetch).toHaveBeenCalledTimes(3);
  });

  it("should throw after exhausting all retries on persistent 403", async () => {
    // All 4 calls return 403
    for (let i = 0; i < 4; i++) {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 403,
        statusText: "Forbidden",
        text: async () => "Persistent auth failure",
      });
    }

    const { invokeLLM } = await import("./_core/llm");
    await expect(
      invokeLLM({ messages: [{ role: "user", content: "test" }] })
    ).rejects.toThrow("LLM invoke failed: 403");

    expect(mockFetch).toHaveBeenCalledTimes(4); // 1 initial + 3 retries
  });

  it("should NOT retry on 400 Bad Request (non-retryable)", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 400,
      statusText: "Bad Request",
      text: async () => "Invalid JSON",
    });

    const { invokeLLM } = await import("./_core/llm");
    await expect(
      invokeLLM({ messages: [{ role: "user", content: "test" }] })
    ).rejects.toThrow("LLM invoke failed: 400");

    expect(mockFetch).toHaveBeenCalledTimes(1); // No retries
  });

  it("should NOT retry on 401 Unauthorized (non-retryable)", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 401,
      statusText: "Unauthorized",
      text: async () => "Invalid API key",
    });

    const { invokeLLM } = await import("./_core/llm");
    await expect(
      invokeLLM({ messages: [{ role: "user", content: "test" }] })
    ).rejects.toThrow("LLM invoke failed: 401");

    expect(mockFetch).toHaveBeenCalledTimes(1); // No retries
  });

  it("should retry on network errors (fetch failed)", async () => {
    // First call: network error
    const networkError = new Error("fetch failed");
    (networkError as any).code = "ECONNRESET";
    mockFetch.mockRejectedValueOnce(networkError);
    // Second call: success
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        id: "test-net",
        created: Date.now(),
        model: "gemini-2.5-flash",
        choices: [{ index: 0, message: { role: "assistant", content: "Reconnected" }, finish_reason: "stop" }],
      }),
    });

    const { invokeLLM } = await import("./_core/llm");
    const result = await invokeLLM({
      messages: [{ role: "user", content: "test" }],
    });

    expect(result.choices[0].message.content).toBe("Reconnected");
    expect(mockFetch).toHaveBeenCalledTimes(2);
  });

  it("should include authorization header with Bearer token", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        id: "test-auth",
        created: Date.now(),
        model: "gemini-2.5-flash",
        choices: [{ index: 0, message: { role: "assistant", content: "OK" }, finish_reason: "stop" }],
      }),
    });

    const { invokeLLM } = await import("./_core/llm");
    await invokeLLM({ messages: [{ role: "user", content: "test" }] });

    expect(mockFetch).toHaveBeenCalledWith(
      expect.stringContaining("/v1/chat/completions"),
      expect.objectContaining({
        headers: expect.objectContaining({
          authorization: "Bearer test-api-key-12345",
        }),
      })
    );
  });

  it("should send correct model and thinking parameters", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        id: "test-params",
        created: Date.now(),
        model: "gemini-2.5-flash",
        choices: [{ index: 0, message: { role: "assistant", content: "OK" }, finish_reason: "stop" }],
      }),
    });

    const { invokeLLM } = await import("./_core/llm");
    await invokeLLM({ messages: [{ role: "user", content: "test" }] });

    const callBody = JSON.parse(mockFetch.mock.calls[0][1].body);
    expect(callBody.model).toBe("gemini-2.5-flash");
    expect(callBody.max_tokens).toBe(32768);
    expect(callBody.thinking).toEqual({ budget_tokens: 128 });
  });
});
