//#shader vertex
#version 330 core

layout (location = 0) in vec3 aPos;
layout (location = 1) in vec3 aNormal;
layout (location = 2) in vec2 aTexCoords;

out vec2 TexCoords;
out vec3 Normal;
out vec3 FragPos;

uniform mat4 model;
uniform mat4 view;
uniform mat4 projection;

void main() {
    FragPos = vec3(model * vec4(aPos, 1.0));
    Normal = mat3(transpose(inverse(model))) * aNormal; // važno za tačne normale
    TexCoords = aTexCoords;
    gl_Position = projection * view * vec4(FragPos, 1.0);
}

//#shader fragment
#version 330 core

out vec4 FragColor;

in vec3 FragPos;
in vec3 Normal;
in vec2 TexCoords;

struct DirectionalLight {
    vec3 direction;
    vec3 color;
};

struct PointLight {
    vec3 position;
    vec3 color;
    float constant;
    float linear;
    float quadratic;
};

uniform float alpha;
uniform sampler2D texture_diffuse1;

uniform DirectionalLight dirLight;
uniform PointLight pointLight;

uniform vec3 viewPos;
uniform float shininess;

vec3 calcDirectionalLight(DirectionalLight light, vec3 normal, vec3 viewDir, vec3 textureColor);
vec3 calcPointLight(PointLight light, vec3 normal, vec3 fragPos, vec3 viewDir, vec3 textureColor);

void main()
{
    vec3 norm = normalize(Normal);
    vec3 viewDir = normalize(viewPos - FragPos);
    vec3 textureColor = texture(texture_diffuse1, TexCoords).rgb;

    // === LIGHTING ===
    vec3 result = vec3(0.0);
    result += calcDirectionalLight(dirLight, norm, viewDir, textureColor);
    result += calcPointLight(pointLight, norm, FragPos, viewDir, textureColor);

    FragColor = vec4(result, alpha);
}


// === DIRECTIONAL LIGHT FUNCTION ===
vec3 calcDirectionalLight(DirectionalLight light, vec3 normal, vec3 viewDir, vec3 textureColor)
{
    vec3 lightDir = normalize(-light.direction);
    // Diffuse
    float diff = max(dot(normal, lightDir), 0.0);
    // Specular
    vec3 reflectDir = reflect(-lightDir, normal);
    float spec = pow(max(dot(viewDir, reflectDir), 0.0), shininess);
    // Combine
    vec3 ambient = 0.1 * light.color * textureColor;
    vec3 diffuse = diff * light.color * textureColor;
    vec3 specular = 0.4 * spec * light.color;
    return ambient + diffuse + specular;
}


// === POINT LIGHT FUNCTION ===
vec3 calcPointLight(PointLight light, vec3 normal, vec3 fragPos, vec3 viewDir, vec3 textureColor)
{
    vec3 lightDir = normalize(light.position - fragPos);
    // Diffuse
    float diff = max(dot(normal, lightDir), 0.0);
    // Specular
    vec3 reflectDir = reflect(-lightDir, normal);
    float spec = pow(max(dot(viewDir, reflectDir), 0.0), shininess);
    // Attenuation
    float distance = length(light.position - fragPos);
    float attenuation = 1.0 / (light.constant + light.linear * distance + light.quadratic * (distance * distance));
    // Combine
    vec3 ambient = 0.05 * light.color * textureColor;
    vec3 diffuse = diff * light.color * textureColor;
    vec3 specular = 0.3 * spec * light.color;
    vec3 result = (ambient + diffuse + specular) * attenuation;
    return result;
}


