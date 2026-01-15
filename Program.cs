using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using System.Threading.RateLimiting;
using System.IdentityModel.Tokens.Jwt;
using System.IO;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "OWASP-Basic API",
        Version = "v1",
        Description = "Baseline API with OWASP-friendly defaults"
    });
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Name = "Authorization",
        Type = SecuritySchemeType.Http,
        Scheme = "bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Description = "Enter: Bearer {your JWT}"
    });
    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            }, new List<string>()
        }
    });
});

// JWT Authentication and Authorization
var jwtIssuer = builder.Configuration["Jwt:Issuer"];
var jwtAudience = builder.Configuration["Jwt:Audience"];
var jwtKey = builder.Configuration["Jwt:SigningKey"];
if (!string.IsNullOrWhiteSpace(jwtKey))
{
    builder.Services.AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    })
    .AddJwtBearer(options =>
    {
        options.RequireHttpsMetadata = true;
        options.SaveToken = false;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = jwtIssuer,
            ValidAudience = jwtAudience,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey!)),
            ClockSkew = TimeSpan.FromSeconds(30)
        };
    });
}

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("OrdersRead", policy =>
        policy.RequireAssertion(ctx =>
        {
            var scopes = ctx.User.FindAll("scope").Select(c => c.Value).ToList();
            return scopes.Any(s => s.Split(' ').Contains("orders:read"));
        }));
    options.AddPolicy("AdminOnly", policy => policy.RequireRole("admin"));
});

// Configure Kestrel security-related options
builder.WebHost.ConfigureKestrel(options =>
{
    options.AddServerHeader = false; // Hide server banner
    options.Limits.MaxRequestBodySize = 1_048_576; // 1 MB max request body
});

// CORS: read allowed origins from configuration
builder.Services.AddCors(options =>
{
    options.AddPolicy("DefaultCors", policy =>
    {
        var origins = builder.Configuration.GetSection("Cors:AllowedOrigins").Get<string[]>() ?? Array.Empty<string>();
        if (origins.Length > 0)
        {
            policy.WithOrigins(origins)
                  .AllowAnyHeader()
                  .AllowAnyMethod()
                  .AllowCredentials();
        }
        else
        {
            policy.AllowAnyOrigin().AllowAnyHeader().AllowAnyMethod();
        }
    });
});

// Global rate limiting by client IP + named policy for tight limits
builder.Services.AddRateLimiter(options =>
{
    options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(httpContext =>
    {
        var ip = httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        return RateLimitPartition.GetFixedWindowLimiter(ip, _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = 100,
            Window = TimeSpan.FromMinutes(1),
            QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
            QueueLimit = 0
        });
    });
    options.AddPolicy("PerUser10PerMin", httpContext =>
    {
        var userKey = httpContext.User.FindFirstValue(ClaimTypes.NameIdentifier)
                      ?? httpContext.User.FindFirst("sub")?.Value
                      ?? httpContext.Connection.RemoteIpAddress?.ToString()
                      ?? "anonymous";
        return RateLimitPartition.GetFixedWindowLimiter(userKey, _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = 10,
            Window = TimeSpan.FromMinutes(1),
            QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
            QueueLimit = 0
        });
    });
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
});

// SSRF-safe HttpClient: allowlisted hosts, no redirects
var allowedHosts = builder.Configuration.GetSection("Outbound:AllowedHosts").Get<string[]>() ?? Array.Empty<string>();
builder.Services.AddHttpClient("SafeExternalClient")
    .ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler
    {
        AllowAutoRedirect = false
    })
    .AddHttpMessageHandler(() => new AllowedHostsHandler(allowedHosts));

var app = builder.Build();

// Configure the HTTP request pipeline.
app.UseSwagger();
app.UseSwaggerUI(c =>
{
    c.SwaggerEndpoint("/swagger/v1/swagger.json", "OWASP-Basic v1");
    c.DisplayOperationId();
    c.EnableTryItOutByDefault();
});
if (!app.Environment.IsDevelopment())
{
    app.UseHsts();
}

// Centralized, safe error handling
app.UseExceptionHandler("/error");

// Only enable HTTPS redirection outside Development to avoid dev warning when no HTTPS port is configured
if (!app.Environment.IsDevelopment())
    app.UseHttpsRedirection();

// Security headers for API responses
app.Use(async (context, next) =>
{
    context.Response.Headers["X-Content-Type-Options"] = "nosniff";
    context.Response.Headers["X-Frame-Options"] = "DENY";
    context.Response.Headers["Referrer-Policy"] = "no-referrer";
    context.Response.Headers["X-Permitted-Cross-Domain-Policies"] = "none";
    await next();
});

// Apply CORS and rate limiting
app.UseCors("DefaultCors");
app.UseRateLimiter();

// AuthZ middlewares
app.UseAuthentication();
app.UseAuthorization();

var summaries = new[]
{
    "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
};

app.MapGet("/weatherforecast", () =>
{
    var forecast =  Enumerable.Range(1, 5).Select(index =>
        new WeatherForecast
        (
            DateOnly.FromDateTime(DateTime.Now.AddDays(index)),
            Random.Shared.Next(-20, 55),
            summaries[Random.Shared.Next(summaries.Length)]
        ))
        .ToArray();
    return forecast;
})
.WithName("GetWeatherForecast")
.WithOpenApi();

// In-memory demo data for orders
var orders = new Dictionary<int, (string ownerSub, string name, decimal amount)>
{
    [1] = ("user-123", "Sample Order A", 10.5m),
    [2] = ("user-456", "Sample Order B", 20m)
};

// Protected endpoint with scope and object-level authorization
app.MapGet("/orders/{id:int}", (HttpContext ctx, int id) =>
{
    if (!orders.TryGetValue(id, out var order))
        return Results.NotFound(new { code = "NOT_FOUND", message = "Resource not found" });

    var sub = ctx.User.FindFirst("sub")?.Value ?? ctx.User.FindFirstValue(ClaimTypes.NameIdentifier);
    if (string.IsNullOrEmpty(sub) || !string.Equals(sub, order.ownerSub, StringComparison.Ordinal))
        return Results.StatusCode(StatusCodes.Status403Forbidden);

    return Results.Ok(new { id, order.name, order.amount });
})
.RequireAuthorization("OrdersRead")
.WithOpenApi();

// Per-endpoint rate limit + pagination example
app.MapGet("/orders", (HttpContext ctx, int page, int pageSize) =>
{
    page = page <= 0 ? 1 : page;
    pageSize = pageSize <= 0 ? 10 : Math.Min(pageSize, 50);

    var ordered = orders.Select(kv => new { id = kv.Key, ownerSub = kv.Value.ownerSub, name = kv.Value.name, amount = kv.Value.amount })
                        .OrderBy(x => x.id)
                        .Skip((page - 1) * pageSize)
                        .Take(pageSize)
                        .ToArray();

    return Results.Ok(new { page, pageSize, items = ordered });
})
.RequireRateLimiting("PerUser10PerMin")
.RequireAuthorization("OrdersRead")
.WithOpenApi();

// Create order with strict input validation (reject unknown fields)
app.MapPost("/orders", async (HttpContext ctx) =>
{
    // Require a non-empty JSON body
    if (ctx.Request.ContentLength.GetValueOrDefault() <= 0)
        return Results.BadRequest(new { code = "VALIDATION_ERROR", message = "Request body is required" });

    string raw;
    using (var reader = new StreamReader(ctx.Request.Body))
    {
        raw = await reader.ReadToEndAsync();
    }
    if (string.IsNullOrWhiteSpace(raw))
        return Results.BadRequest(new { code = "VALIDATION_ERROR", message = "Request body must be valid JSON" });

    JsonDocument doc;
    try { doc = JsonDocument.Parse(raw); }
    catch (JsonException) { return Results.BadRequest(new { code = "VALIDATION_ERROR", message = "Malformed JSON" }); }

    var allowed = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "name", "amount" };
    var props = doc.RootElement.EnumerateObject().ToList();
    if (props.Any(p => !allowed.Contains(p.Name)))
        return Results.BadRequest(new { code = "VALIDATION_ERROR", message = "Unknown fields present" });

    if (!doc.RootElement.TryGetProperty("name", out var nameProp) || nameProp.ValueKind != JsonValueKind.String)
        return Results.BadRequest(new { code = "VALIDATION_ERROR", message = "Invalid or missing 'name'" });
    if (!doc.RootElement.TryGetProperty("amount", out var amountProp) || amountProp.ValueKind != JsonValueKind.Number)
        return Results.BadRequest(new { code = "VALIDATION_ERROR", message = "Invalid or missing 'amount'" });

    var name = nameProp.GetString()!;
    var amount = amountProp.GetDecimal();
    if (string.IsNullOrWhiteSpace(name) || amount <= 0)
        return Results.BadRequest(new { code = "VALIDATION_ERROR", message = "Name must be non-empty and amount > 0" });

    var sub = ctx.User.FindFirst("sub")?.Value ?? ctx.User.FindFirstValue(ClaimTypes.NameIdentifier);
    if (string.IsNullOrEmpty(sub)) return Results.StatusCode(StatusCodes.Status401Unauthorized);

    var nextId = orders.Keys.DefaultIfEmpty(0).Max() + 1;
    orders[nextId] = (sub, name, amount);
    return Results.Created($"/orders/{nextId}", new { id = nextId, name, amount });
})
.RequireRateLimiting("PerUser10PerMin")
.RequireAuthorization("OrdersRead")
.WithMetadata(new Microsoft.AspNetCore.Mvc.ConsumesAttribute("application/json"))
.WithOpenApi(op =>
{
    op.RequestBody = new Microsoft.OpenApi.Models.OpenApiRequestBody
    {
        Required = true,
        Content = new System.Collections.Generic.Dictionary<string, Microsoft.OpenApi.Models.OpenApiMediaType>
        {
            ["application/json"] = new Microsoft.OpenApi.Models.OpenApiMediaType
            {
                Schema = new Microsoft.OpenApi.Models.OpenApiSchema
                {
                    Type = "object",
                    Properties = new System.Collections.Generic.Dictionary<string, Microsoft.OpenApi.Models.OpenApiSchema>
                    {
                        ["name"] = new Microsoft.OpenApi.Models.OpenApiSchema { Type = "string" },
                        ["amount"] = new Microsoft.OpenApi.Models.OpenApiSchema { Type = "number", Format = "decimal" }
                    },
                    Required = new System.Collections.Generic.HashSet<string> { "name", "amount" },
                    AdditionalPropertiesAllowed = false
                },
                Example = new Microsoft.OpenApi.Any.OpenApiObject
                {
                    ["name"] = new Microsoft.OpenApi.Any.OpenApiString("Sample Order"),
                    ["amount"] = new Microsoft.OpenApi.Any.OpenApiDouble(12.34)
                }
            }
        }
    };
    return op;
});

// SSRF-safe outbound call example
app.MapGet("/external/image-meta", async (IHttpClientFactory httpClientFactory, string url) =>
{
    if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
        return Results.BadRequest(new { code = "VALIDATION_ERROR", message = "Invalid URL" });

    var client = httpClientFactory.CreateClient("SafeExternalClient");
    using var req = new HttpRequestMessage(HttpMethod.Head, uri);
    using var resp = await client.SendAsync(req);
    return Results.Ok(new { uri = uri.ToString(), status = (int)resp.StatusCode, contentType = resp.Content.Headers.ContentType?.ToString() });
})
.WithOpenApi();

// Map error endpoint before starting the app
app.Map("/error", (HttpContext http) =>
{
    return Results.Problem(title: "An unexpected error occurred.", statusCode: StatusCodes.Status500InternalServerError);
});

// Map token issuing and demo endpoints before app.Run
// Replace token endpoint with flexible issuance without username/password
// Supports POST with optional JSON body and GET with query params (sub, scopes, admin)
Func<HttpContext, Task<IResult>> issueToken = async (HttpContext ctx) =>
{
    string sub = "user-123";
    string scopes = "orders:read";
    bool isAdmin = false;

    // Try read body if present
    string? raw = null;
    var hasBody = ctx.Request.ContentLength.GetValueOrDefault() > 0;
    if (hasBody)
    {
        using var reader = new StreamReader(ctx.Request.Body);
        raw = await reader.ReadToEndAsync();
    }
    if (!string.IsNullOrWhiteSpace(raw))
    {
        try
        {
            using var doc = JsonDocument.Parse(raw);
            if (doc.RootElement.TryGetProperty("sub", out var subProp) && subProp.ValueKind == JsonValueKind.String)
                sub = subProp.GetString()!;
            if (doc.RootElement.TryGetProperty("scopes", out var scopesProp) && scopesProp.ValueKind == JsonValueKind.String)
                scopes = scopesProp.GetString()!;
            if (doc.RootElement.TryGetProperty("admin", out var adminProp))
                isAdmin = adminProp.ValueKind == JsonValueKind.True ||
                          (adminProp.ValueKind == JsonValueKind.String &&
                           (string.Equals(adminProp.GetString(), "true", StringComparison.OrdinalIgnoreCase) ||
                            string.Equals(adminProp.GetString(), "1", StringComparison.OrdinalIgnoreCase)));
        }
        catch
        {
            // ignore malformed body and fall back to defaults
        }
    }

    // Override via query params if provided
    var q = ctx.Request.Query;
    if (q.TryGetValue("sub", out var subQ) && !string.IsNullOrWhiteSpace(subQ))
        sub = subQ!;
    if (q.TryGetValue("scopes", out var scopesQ) && !string.IsNullOrWhiteSpace(scopesQ))
        scopes = scopesQ!;
    if (q.TryGetValue("admin", out var adminQ))
    {
        var val = adminQ.ToString();
        isAdmin = val.Equals("true", StringComparison.OrdinalIgnoreCase) || val == "1" || val.Equals("yes", StringComparison.OrdinalIgnoreCase) || val.Equals("on", StringComparison.OrdinalIgnoreCase);
    }

    if (string.IsNullOrWhiteSpace(jwtKey))
        return Results.Problem("JWT signing key not configured.", statusCode: StatusCodes.Status500InternalServerError);

    var claims = new List<Claim>
    {
        new Claim("sub", sub),
        new Claim(ClaimTypes.NameIdentifier, sub),
        new Claim("scope", scopes)
    };
    if (isAdmin)
    {
        claims.Add(new Claim(ClaimTypes.Role, "admin"));
    }

    var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey!));
    var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

    var token = new JwtSecurityToken(
        issuer: jwtIssuer,
        audience: jwtAudience,
        claims: claims,
        expires: DateTime.UtcNow.AddMinutes(15),
        signingCredentials: credentials);

    var tokenString = new JwtSecurityTokenHandler().WriteToken(token);

    return Results.Ok(new { access_token = tokenString, token_type = "Bearer", expires_in = 900 });
};

// Map both POST and GET for convenience
app.MapPost("/auth/token", issueToken)
   .AllowAnonymous()
   .WithOpenApi();
app.MapGet("/auth/token", issueToken)
   .AllowAnonymous()
   .WithOpenApi();

app.MapGet("/admin/ping", () => Results.Ok(new { status = "ok" }))
.RequireAuthorization("AdminOnly")
.WithOpenApi();

app.MapGet("/me", (HttpContext ctx) =>
{
    if (ctx.User?.Identity?.IsAuthenticated != true)
        return Results.Unauthorized();
    var roles = ctx.User.FindAll(ClaimTypes.Role).Select(c => c.Value).ToArray();
    var scopesAll = ctx.User.FindAll("scope").Select(c => c.Value).SelectMany(s => s.Split(' ', StringSplitOptions.RemoveEmptyEntries)).Distinct().ToArray();
    var subVal = ctx.User.FindFirst("sub")?.Value ?? ctx.User.FindFirstValue(ClaimTypes.NameIdentifier);
    return Results.Ok(new { sub = subVal, roles, scopes = scopesAll });
})
.RequireAuthorization()
.WithOpenApi();

app.Run();

record WeatherForecast(DateOnly Date, int TemperatureC, string? Summary)
{
    public int TemperatureF => 32 + (int)(TemperatureC / 0.5556);
}

// Delegating handler enforcing allowlisted outbound hosts
class AllowedHostsHandler : DelegatingHandler
{
    private readonly HashSet<string> _allowedHosts;
    public AllowedHostsHandler(IEnumerable<string> allowedHosts)
    {
        _allowedHosts = new HashSet<string>(allowedHosts ?? Array.Empty<string>(), StringComparer.OrdinalIgnoreCase);
    }
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var host = request.RequestUri?.Host;
        if (string.IsNullOrWhiteSpace(host) || !_allowedHosts.Contains(host))
        {
            var response = new HttpResponseMessage(System.Net.HttpStatusCode.Forbidden)
            {
                Content = new StringContent("Outbound host not allowed")
            };
            return Task.FromResult(response);
        }
        return base.SendAsync(request, cancellationToken);
    }
}
