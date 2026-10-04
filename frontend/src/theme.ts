export type Theme = "dark" | "light";

const KEY = "accessops-theme";

/** The visitor's saved theme; dark when unset or when storage is unavailable. */
export function storedTheme(): Theme {
  try {
    return localStorage.getItem(KEY) === "light" ? "light" : "dark";
  } catch {
    return "dark";
  }
}

/** Applies a theme to the document. Called before the first render to avoid a flash. */
export function applyTheme(theme: Theme) {
  document.documentElement.dataset.theme = theme;
  document
    .querySelector('meta[name="theme-color"]')
    ?.setAttribute("content", theme === "dark" ? "#0b0e13" : "#f3f5f8");
}

export function saveTheme(theme: Theme) {
  try {
    localStorage.setItem(KEY, theme);
  } catch {
    /* Storage can be unavailable; the theme still applies for this visit. */
  }
}
