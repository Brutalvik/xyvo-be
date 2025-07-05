import { query } from "../utils/db.mjs";

/** @param {import('fastify').FastifyInstance} app */
export async function docsRoutes(app) {
  app.get("/", async (req, reply) => {
    let dbStatus = { connected: false, time: null };

    try {
      const res = await query("SELECT NOW()");
      dbStatus.connected = true;
      dbStatus.time = res.rows[0].now;
    } catch (e) {
      dbStatus.connected = false;
    }

    const printed = app.printRoutes();
    const routes = parseRouteTree(printed);

    // If the tree parsing doesn't work well, fall back to a simpler approach
    if (routes.length === 0) {
      // Fallback: extract routes from the printed output using a different method
      const lines = printed
        .split("\n")
        .filter((line) => line.includes("(") && line.includes(")"));
      const fallbackRoutes = [];

      for (const line of lines) {
        const methodMatch = line.match(/\(([^)]+)\)/);
        if (methodMatch) {
          const methods = methodMatch[1].split(",").map((m) => m.trim());
          // This is a simplified fallback - you might need to adjust based on actual output
          const pathMatch = line
            .replace(/[├└│─]/g, "")
            .trim()
            .replace(/\s*\([^)]+\)$/, "");
          if (pathMatch) {
            methods.forEach((method) => {
              if (method !== "OPTIONS") {
                fallbackRoutes.push({
                  method,
                  url: pathMatch.startsWith("/") ? pathMatch : "/" + pathMatch,
                });
              }
            });
          }
        }
      }
      routes.push(...fallbackRoutes);
    }

    const grouped = groupRoutes(routes);

    return reply.type("text/html").send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>API Route Explorer</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script>
    function toggle(id) {
      const el = document.getElementById(id);
      el.classList.toggle('hidden');
    }
    function toggleAll(expand) {
      const divs = document.querySelectorAll('[id^="route-"]');
      divs.forEach(d => d.classList.toggle('hidden', !expand));
    }
    function filterByMethod(method) {
      const all = document.querySelectorAll('.route-item');
      all.forEach(i => {
        const routeMethod = i.dataset.method;
        if (method === 'ALL' || routeMethod === method) {
          i.classList.remove('hidden');
        } else {
          i.classList.add('hidden');
        }
      });
    }
  </script>
  <style>
    .method-GET { background-color: #d1fae5; color: #065f46; }
    .method-POST { background-color: #dbeafe; color: #1e40af; }
    .method-PATCH { background-color: #fef3c7; color: #92400e; }
    .method-DELETE { background-color: #fee2e2; color: #991b1b; }
    .method-PUT { background-color: #e0f2fe; color: #075985; }
    .method-HEAD { background-color: #ede9fe; color: #5b21b6; }
  </style>
</head>
<body class="bg-gray-50 text-gray-800 font-sans p-6">
  <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 mb-6">
    <div class="flex items-center space-x-4">
      <h1 class="text-3xl font-bold">📘 API Route Explorer</h1>
      <div class="flex items-center space-x-2">
        <span class="text-sm text-gray-600">DB Status:</span>
        <div class="flex items-center space-x-1">
          <div class="w-3 h-3 rounded-full ${
            dbStatus.connected ? "bg-green-500" : "bg-red-500"
          }"></div>
          <span class="text-sm ${
            dbStatus.connected ? "text-green-600" : "text-red-600"
          } font-medium">
            ${dbStatus.connected ? "Connected" : "Disconnected"}
          </span>
        </div>
      </div>
    </div>
    <div class="space-x-2">
      <select onchange="filterByMethod(this.value)" class="text-sm border border-gray-300 rounded px-2 py-1">
        <option value="ALL">All Methods</option>
        <option value="GET">GET</option>
        <option value="POST">POST</option>
        <option value="PUT">PUT</option>
        <option value="PATCH">PATCH</option>
        <option value="DELETE">DELETE</option>
        <option value="HEAD">HEAD</option>
      </select>
      <button onclick="toggleAll(true)" class="px-3 py-1 bg-blue-100 text-blue-700 rounded hover:bg-blue-200 text-sm font-medium">Expand All</button>
      <button onclick="toggleAll(false)" class="px-3 py-1 bg-gray-100 text-gray-700 rounded hover:bg-gray-200 text-sm font-medium">Collapse All</button>
    </div>
  </div>

  <div class="space-y-4">
    ${Object.entries(grouped)
      .map(
        ([prefix, routes], i) => `
      <div class="border border-gray-300 rounded">
        <button onclick="toggle('route-${i}')" class="w-full text-left px-4 py-2 bg-gray-100 hover:bg-gray-200 font-semibold">
          ${prefix} (${routes.length})
        </button>
        <div id="route-${i}" class="hidden px-4 py-2 space-y-1">
          ${routes
            .map(
              (r) => `
              <div class="route-item text-sm font-mono flex items-center space-x-2" data-method="${r.method}">
                <span class="inline-block px-2 py-1 rounded font-bold method-${r.method}">${r.method}</span>
                <span class="text-gray-800">${r.url}</span>
              </div>
            `
            )
            .join("")}
        </div>
      </div>
    `
      )
      .join("")}
  </div>
</body>
</html>`);
  });
}

function parseRouteTree(treeOutput) {
  const lines = treeOutput.split("\n");
  const routes = [];
  const pathStack = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Skip empty lines and the root node line
    if (!line.trim() || line.includes("(empty root node)")) {
      continue;
    }

    // Calculate the depth based on tree characters
    const depth = getDepth(line);

    // Adjust the path stack to the current depth
    pathStack.length = depth;

    // Extract the path segment and methods
    const cleanLine = line.replace(/[├└│─]/g, "").trim();
    const methodMatch = cleanLine.match(/\(([^)]+)\)$/);

    if (methodMatch) {
      // This line has methods, so it's a route endpoint
      const methods = methodMatch[1].split(",").map((m) => m.trim());
      const pathSegment = cleanLine.replace(/\s*\([^)]+\)$/, "").trim();

      // Add current segment to path stack
      if (pathSegment && pathSegment !== "/") {
        pathStack[depth] = pathSegment;
      }

      // Build the full path
      let fullPath = "/" + pathStack.filter(Boolean).join("/");

      // Clean up the path
      fullPath = fullPath.replace(/\/+/g, "/");
      if (fullPath !== "/" && fullPath.endsWith("/")) {
        fullPath = fullPath.slice(0, -1);
      }

      // Add routes for each method
      methods.forEach((method) => {
        if (method !== "OPTIONS") {
          // Skip OPTIONS for cleaner display
          routes.push({
            method: method.trim(),
            url: fullPath,
          });
        }
      });
    } else {
      // This line is just a path segment
      const pathSegment = cleanLine.replace(/\/$/, ""); // Remove trailing slash
      if (pathSegment && pathSegment !== "/") {
        pathStack[depth] = pathSegment;
      }
    }
  }

  return routes;
}

function getDepth(line) {
  let depth = 0;
  let i = 0;

  while (i < line.length) {
    const char = line[i];
    if (char === "├" || char === "└" || char === "│") {
      depth++;
      i++;
      // Skip the following connection characters
      while (i < line.length && (line[i] === "─" || line[i] === " ")) {
        i++;
      }
    } else if (char === " ") {
      i++;
    } else {
      break;
    }
  }

  return depth;
}

function groupRoutes(routes) {
  const groups = {};

  for (const route of routes) {
    const groupKey = determineGroupKey(route.url);
    if (!groups[groupKey]) {
      groups[groupKey] = [];
    }
    groups[groupKey].push(route);
  }

  // Sort groups by key
  return Object.fromEntries(
    Object.entries(groups).sort(([a], [b]) => a.localeCompare(b))
  );
}

function determineGroupKey(url) {
  // Clean up the URL first
  url = url.trim();
  if (!url.startsWith("/")) {
    url = "/" + url;
  }

  const segments = url.split("/").filter(Boolean);

  // Handle root path
  if (segments.length === 0) {
    return "Root";
  }

  const first = segments[0];

  // Group by main resource/feature based on actual routes
  switch (first) {
    case "auth":
      return "Authentication";
    case "users":
      return "Users";
    case "organizations":
      return "Organizations";
    case "projects":
      return "Projects";
    case "tasks":
      return "Tasks";
    case "teams":
      return "Teams";
    case "sprints":
      return "Sprints";
    case "backlogs":
      return "Backlogs";
    default:
      return capitalize(first);
  }
}

function isParameterSegment(segment) {
  return (
    segment &&
    (segment.startsWith(":") ||
      /^\d+$/.test(segment) ||
      segment.toLowerCase().includes("id") ||
      segment.startsWith("{") ||
      segment.includes("*"))
  );
}

function capitalize(str) {
  return str.charAt(0).toUpperCase() + str.slice(1);
}
