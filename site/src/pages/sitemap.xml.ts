import type { APIRoute } from "astro";
import { PUBLIC_ROUTES } from "../config/launch";
export const GET: APIRoute = ({ site }) => {
  const origin = site ?? new URL("https://shadowpath.coriolislabs.ca");
  const urls = PUBLIC_ROUTES.map((path) => `<url><loc>${new URL(path, origin).href}</loc></url>`).join("");
  return new Response(`<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">${urls}</urlset>`, {
    headers: { "Content-Type": "application/xml; charset=utf-8" },
  });
};
