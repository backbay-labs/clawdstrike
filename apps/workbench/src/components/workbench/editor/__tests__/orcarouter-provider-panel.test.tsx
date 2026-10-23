import { describe, expect, it, vi, beforeEach, type Mock } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { OrcaRouterProviderPanel } from "../orcarouter-provider-panel";
import { OrcaRouterCredentialManager, createMemoryPersistence } from "@/lib/orcarouter/credentials";
import { resolveOrcaRouterOrigins } from "@/lib/orcarouter/provider";

const origins = {
  authBaseUrl: "https://www.orcarouter.ai",
  apiBaseUrl: "https://api.orcarouter.ai/v1",
};

const CATALOG = {
  data: [
    {
      id: "orcarouter/auto",
      name: "OrcaRouter Auto",
      supported_endpoint_types: ["openai"],
      architecture: { input_modalities: ["text", "image"] },
    },
    {
      id: "orcacyber-ultra-1.0",
      name: "OrcaCyber Ultra",
      supported_endpoint_types: ["openai"],
      architecture: { input_modalities: ["text"] },
    },
    {
      id: "text-embedding-3-small",
      supported_endpoint_types: ["openai", "embeddings"],
      architecture: { input_modalities: ["text"] },
    },
  ],
};

const TEST_KEY = "sk-orca-testkey123456";

function makeFetch(overrides?: { catalogStatus?: number }) {
  return vi.fn<typeof fetch>(async (input) => {
    const url = String(input);
    if (url.endsWith("/models")) {
      if (overrides?.catalogStatus && overrides.catalogStatus !== 200) {
        return new Response("", { status: overrides.catalogStatus });
      }
      return new Response(JSON.stringify(CATALOG), { status: 200 });
    }
    if (url.endsWith("/auth/keys")) {
      return new Response(
        JSON.stringify({ key: TEST_KEY, user_id: "77", scope: "api" }),
        { status: 200 },
      );
    }
    return new Response("{}", { status: 200 });
  });
}

function renderPanel(props: Partial<Parameters<typeof OrcaRouterProviderPanel>[0]> = {}) {
  const persistence = createMemoryPersistence();
  const manager = new OrcaRouterCredentialManager({ origins, persistence });
  const selection = props.selection ?? { embeddingModel: "", chatModel: "" };
  const onSelectionChange = props.onSelectionChange ?? vi.fn();
  const openExternalMock = vi.fn<(url: string) => void>();
  const openExternal = props.openExternal ?? openExternalMock;
  const fetchFn = (props.fetchFn ?? makeFetch()) as unknown as Mock;

  const utils = render(
    <OrcaRouterProviderPanel
      selection={selection}
      onSelectionChange={onSelectionChange}
      credentialManager={manager}
      origins={origins}
      fetchFn={fetchFn}
      openExternal={openExternal}
    />,
  );
  return { ...utils, manager, onSelectionChange, openExternal: openExternalMock, fetchFn, persistence };
}

async function saveKey(user: ReturnType<typeof userEvent.setup>) {
  await user.type(screen.getByTestId("orcarouter-api-key-input"), TEST_KEY);
  await user.click(screen.getByTestId("orcarouter-save-key"));
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe("authentication choices", () => {
  it("shows API key and Connect with OrcaRouter side by side", () => {
    renderPanel();
    expect(screen.getByTestId("orcarouter-auth-tab-api-key")).toBeInTheDocument();
    expect(screen.getByTestId("orcarouter-auth-tab-pkce")).toHaveTextContent(
      /Connect with OrcaRouter/,
    );
    const input = screen.getByTestId("orcarouter-api-key-input");
    expect(input).toHaveAttribute("type", "password");
    expect(screen.getByTestId("orcarouter-save-key")).toBeDisabled();
  });

  it("saves an API key and shows it masked", async () => {
    const user = userEvent.setup();
    const { fetchFn } = renderPanel();

    await saveKey(user);

    await waitFor(() =>
      expect(screen.getByTestId("orcarouter-masked-key")).toBeInTheDocument(),
    );
    expect(screen.getByTestId("orcarouter-masked-key").textContent).not.toContain(TEST_KEY);
    expect(fetchFn).toHaveBeenCalledWith(
      "https://api.orcarouter.ai/v1/models",
      expect.objectContaining({
        headers: expect.objectContaining({ Authorization: `Bearer ${TEST_KEY}` }),
      }),
    );
  });

  it("rejects a malformed key with an actionable message", async () => {
    const user = userEvent.setup();
    renderPanel();
    await user.type(screen.getByTestId("orcarouter-api-key-input"), "sk-proj-nope");
    await user.click(screen.getByTestId("orcarouter-save-key"));
    expect(await screen.findByTestId("orcarouter-key-hint")).toHaveTextContent(/sk-orca/);
  });

  it("clears a stored credential", async () => {
    const user = userEvent.setup();
    const { persistence, manager } = renderPanel();
    await saveKey(user);
    await waitFor(() => expect(manager.getCurrent()).not.toBeNull());
    await user.click(screen.getByTestId("orcarouter-clear-credential"));
    await waitFor(() => expect(manager.getCurrent()).toBeNull());
    expect(await persistence.get("orcarouter_api_key")).toBeNull();
  });
});

describe("PKCE connect flow", () => {
  it("starts an out-of-band authorization and opens the consent URL", async () => {
    const user = userEvent.setup();
    const { openExternal } = renderPanel();

    await user.click(screen.getByTestId("orcarouter-auth-tab-pkce"));
    await user.click(screen.getByTestId("orcarouter-connect-button"));

    await waitFor(() => expect(openExternal).toHaveBeenCalledTimes(1));
    const url = new URL(String(openExternal.mock.calls[0][0]));
    expect(url.origin).toBe("https://www.orcarouter.ai");
    expect(url.pathname).toBe("/auth");
    expect(url.searchParams.get("callback_url")).toBe("oob");
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
    expect(url.searchParams.get("code_challenge")).toBeTruthy();
    // The verifier never appears on the consent URL.
    expect(url.toString()).not.toContain("code_verifier");
  });

  it("exchanges the pasted code on the auth origin and stores the key", async () => {
    const user = userEvent.setup();
    const { fetchFn, manager } = renderPanel();

    await user.click(screen.getByTestId("orcarouter-auth-tab-pkce"));
    await user.click(screen.getByTestId("orcarouter-connect-button"));
    await user.type(await screen.findByTestId("orcarouter-code-input"), "the-code");
    await user.click(screen.getByTestId("orcarouter-complete-connect"));

    await waitFor(() => expect(screen.getByTestId("orcarouter-masked-key")).toBeInTheDocument());
    const exchangeCall = fetchFn.mock.calls.find((call: unknown[]) =>
      String(call[0]).includes("/auth/keys"),
    );
    expect(String(exchangeCall?.[0])).toBe("https://www.orcarouter.ai/api/v1/auth/keys");
    expect(manager.getCurrent()?.source).toBe("pkce");
  });

  it("surfaces a denial and releases the busy state", async () => {
    const user = userEvent.setup();
    const fetchFn = vi.fn<typeof fetch>(async (input) => {
      if (String(input).endsWith("/models")) {
        return new Response(JSON.stringify(CATALOG), { status: 200 });
      }
      return new Response("", { status: 403 });
    });
    renderPanel({ fetchFn });

    await user.click(screen.getByTestId("orcarouter-auth-tab-pkce"));
    await user.click(screen.getByTestId("orcarouter-connect-button"));
    await user.type(await screen.findByTestId("orcarouter-code-input"), "used-code");
    await user.click(screen.getByTestId("orcarouter-complete-connect"));

    expect(await screen.findByTestId("orcarouter-connect-error")).toHaveTextContent(/expired|used/i);
    expect(screen.getByTestId("orcarouter-complete-connect")).not.toBeDisabled();
  });

  it("clears busy state on pagehide and allows a second login without remounting", async () => {
    const user = userEvent.setup();
    const { openExternal } = renderPanel();

    await user.click(screen.getByTestId("orcarouter-auth-tab-pkce"));
    await user.click(screen.getByTestId("orcarouter-connect-button"));
    await screen.findByTestId("orcarouter-code-input");

    window.dispatchEvent(new Event("pagehide"));

    await waitFor(() =>
      expect(screen.queryByTestId("orcarouter-code-input")).not.toBeInTheDocument(),
    );
    expect(screen.getByTestId("orcarouter-connect-button")).toBeInTheDocument();

    // A second login must start from the same mounted component.
    await user.click(screen.getByTestId("orcarouter-connect-button"));
    await waitFor(() => expect(openExternal).toHaveBeenCalledTimes(2));
    expect(screen.getByTestId("orcarouter-authorize-url")).toBeInTheDocument();
  });

  it("cancel returns to the idle state", async () => {
    const user = userEvent.setup();
    renderPanel();
    await user.click(screen.getByTestId("orcarouter-auth-tab-pkce"));
    await user.click(screen.getByTestId("orcarouter-connect-button"));
    await user.click(await screen.findByTestId("orcarouter-cancel-connect"));
    expect(screen.getByTestId("orcarouter-connect-button")).toBeInTheDocument();
  });
});

describe("catalogue-driven model selectors", () => {
  it("populates the text dropdown from the live catalogue and opens it", async () => {
    const user = userEvent.setup();
    const { onSelectionChange } = renderPanel();
    await saveKey(user);

    const trigger = await screen.findByTestId("orcarouter-chat-model-trigger");
    await waitFor(() => expect(trigger).not.toBeDisabled());
    await user.click(trigger);

    const panel = screen.getByTestId("orcarouter-chat-model-panel");
    expect(panel).toBeInTheDocument();
    expect(screen.getByTestId("orcarouter-chat-model-option-orcarouter/auto")).toBeInTheDocument();
    expect(
      screen.getByTestId("orcarouter-chat-model-option-orcacyber-ultra-1.0"),
    ).toBeInTheDocument();
    // Embedding-only models never appear in the chat selector.
    expect(
      screen.queryByTestId("orcarouter-chat-model-option-text-embedding-3-small"),
    ).not.toBeInTheDocument();

    await user.click(screen.getByTestId("orcarouter-chat-model-option-orcarouter/auto"));
    expect(onSelectionChange).toHaveBeenCalledWith(
      expect.objectContaining({ chatModel: "orcarouter/auto" }),
    );
  });

  it("keeps embedding-only models in the embedding selector", async () => {
    const user = userEvent.setup();
    renderPanel();
    await saveKey(user);

    const trigger = await screen.findByTestId("orcarouter-embedding-model-trigger");
    await waitFor(() => expect(trigger).not.toBeDisabled());
    await user.click(trigger);

    expect(
      screen.getByTestId("orcarouter-embedding-model-option-text-embedding-3-small"),
    ).toBeInTheDocument();
    expect(
      screen.queryByTestId("orcarouter-embedding-model-option-orcacyber-ultra-1.0"),
    ).not.toBeInTheDocument();
  });

  it("clears a selection the catalogue no longer supports", async () => {
    const user = userEvent.setup();
    const onSelectionChange = vi.fn();
    renderPanel({
      selection: { embeddingModel: "gone/model", chatModel: "" },
      onSelectionChange,
    });
    await saveKey(user);
    await waitFor(() =>
      expect(onSelectionChange).toHaveBeenCalledWith(
        expect.objectContaining({ embeddingModel: "" }),
      ),
    );
  });

  it("shows a degraded note when the catalogue fails", async () => {
    const user = userEvent.setup();
    const { fetchFn } = renderPanel({ fetchFn: makeFetch({ catalogStatus: 500 }) });
    await saveKey(user);
    expect(await screen.findByTestId("orcarouter-catalog-note")).toHaveTextContent(
      /verified model seed/i,
    );
    expect(screen.getByTestId("orcarouter-catalog-status")).toHaveTextContent(/degraded/);
    expect(fetchFn).toHaveBeenCalled();
  });

  it("falls back to the verified embedding route when the live catalogue has none", async () => {
    const chatOnly = {
      data: [
        {
          id: "orcarouter/auto",
          supported_endpoint_types: ["openai"],
          architecture: { input_modalities: ["text"] },
        },
        {
          id: "orca/orcacyber-ultra-1.0",
          name: "OrcaCyber Ultra",
          supported_endpoint_types: ["openai"],
          architecture: { input_modalities: ["text"] },
        },
      ],
    };
    const fetchFn = vi.fn<typeof fetch>(async (input) =>
      String(input).endsWith("/models")
        ? new Response(JSON.stringify(chatOnly), { status: 200 })
        : new Response("{}", { status: 200 }),
    );
    const user = userEvent.setup();
    renderPanel({ fetchFn });

    await saveKey(user);
    expect(await screen.findByTestId("orcarouter-embedding-fallback-note")).toHaveTextContent(
      /orcarouter\/auto/,
    );

    const trigger = screen.getByTestId("orcarouter-embedding-model-trigger");
    expect(trigger).not.toBeDisabled();
    await user.click(trigger);
    expect(
      screen.getByTestId("orcarouter-embedding-model-option-orcarouter/auto"),
    ).toBeInTheDocument();
  });

  it("marks the live cyber tier with its `orca/` namespace", async () => {
    const live = {
      data: [
        {
          id: "orcarouter/auto",
          supported_endpoint_types: ["openai"],
          architecture: { input_modalities: ["text"] },
        },
        {
          id: "orca/orcacyber-zero-1.5",
          name: "OrcaCyber Zero",
          supported_endpoint_types: ["openai"],
          architecture: { input_modalities: ["text"] },
        },
        {
          id: "text-embedding-3-small",
          supported_endpoint_types: ["openai", "embeddings"],
          architecture: { input_modalities: ["text"] },
        },
      ],
    };
    const fetchFn = vi.fn<typeof fetch>(async (input) =>
      String(input).endsWith("/models")
        ? new Response(JSON.stringify(live), { status: 200 })
        : new Response("{}", { status: 200 }),
    );
    const user = userEvent.setup();
    renderPanel({ fetchFn });

    await saveKey(user);
    await user.click(await screen.findByTestId("orcarouter-chat-model-trigger"));

    const options = screen.getAllByRole("option");
    // Default first, dedicated cyber tier next.
    expect(options[0]).toHaveTextContent(/orcarouter\/auto · default/);
    expect(options[1]).toHaveTextContent(/orca\/orcacyber-zero-1\.5/);
    expect(options[1]).toHaveTextContent(/cyber/);
  });
});
