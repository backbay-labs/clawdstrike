// Star Nest — port of Shadertoy XlfGRj by Pablo Roman Andrioli
// Subtle parameters for observatory background: low brightness, moderate saturation
// GLSL ES 3.00 compatible

uniform float time;
uniform vec2 resolution;

varying vec2 vUv;

// Star Nest parameters
#define iterations 17
#define formuparam 0.53

#define volsteps 15
#define stepsize 0.12

#define zoom 0.800
#define tile 0.850
#define speed 0.010

#define brightness 0.003
#define darkmatter 0.300
#define distfading 0.730
#define saturation 0.650

void main() {
  // Map UVs to screen coordinates
  vec2 uv = vUv - 0.5;
  uv.y *= resolution.y / resolution.x;

  // Camera direction
  vec3 dir = vec3(uv * zoom, 1.0);
  float t = time * speed + 0.25;

  // Rotation matrix
  float a1 = 0.5 / resolution.x * 2.0;
  float a2 = 0.8 / resolution.y * 2.0;
  mat2 rot1 = mat2(cos(a1), sin(a1), -sin(a1), cos(a1));
  mat2 rot2 = mat2(cos(a2), sin(a2), -sin(a2), cos(a2));
  dir.xz *= rot1;
  dir.xy *= rot2;

  vec3 from = vec3(1.0, 0.5, 0.5);
  from += vec3(t * 2.0, t, -2.0);
  from.xz *= rot1;
  from.xy *= rot2;

  // Volumetric rendering
  float s = 0.1;
  float fade = 1.0;
  vec3 v = vec3(0.0);

  for (int r = 0; r < volsteps; r++) {
    vec3 p = from + s * dir * 0.5;
    p = abs(vec3(tile) - mod(p, vec3(tile * 2.0)));

    float pa;
    float a = pa = 0.0;

    for (int i = 0; i < iterations; i++) {
      p = abs(p) / dot(p, p) - formuparam;
      a += abs(length(p) - pa);
      pa = length(p);
    }

    float dm = max(0.0, darkmatter - a * a * 0.001);
    a *= a * a;
    if (r > 6) {
      fade *= 1.0 - dm;
    }

    v += fade;
    v += vec3(s, s * s, s * s * s * s) * a * brightness * fade;
    fade *= distfading;
    s += stepsize;
  }

  v = mix(vec3(length(v)), v, saturation);

  // Tone-map to [0, 1]
  gl_FragColor = vec4(v * 0.01, 1.0);
}
