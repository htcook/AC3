import { createContext, useContext } from "react";

/**
 * EmbedContext — When true, sub-pages skip their AppShell wrapper.
 * Used by HubTabs to embed sub-pages as tab content without double-wrapping.
 */
const EmbedContext = createContext(false);

export const EmbedProvider = ({ children }: { children: React.ReactNode }) => (
  <EmbedContext.Provider value={true}>{children}</EmbedContext.Provider>
);

export const useIsEmbedded = () => useContext(EmbedContext);
