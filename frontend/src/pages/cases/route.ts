export const selectedCaseId = () =>
  new URLSearchParams(location.hash.split("?")[1]).get("case");

export function openCase(id?: string) {
  location.hash = `/cases${id ? `?case=${encodeURIComponent(id)}` : ""}`;
}
