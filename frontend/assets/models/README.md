# 3D asset source policy

UniHack uses procedural geometry for changing workflow and scan data. Put editable source models in this directory only when a stable visual element cannot be represented procedurally.

Before adding a runtime model:

1. Record its name, author, source URL, license, and changes in `frontend/public/models/model-manifest.json`.
2. Run `npm run assets:inspect -- <source.glb>`.
3. Optimize it with `npm run assets:optimize -- <source.glb> <runtime.glb> --compress draco --texture-compress webp`.
4. Keep each optimized model at or below 1.5 MB, textures at or below 2K, and all initially loaded scene assets at or below 3 MB compressed.
5. Copy only the optimized GLB and local decoders into `frontend/public/models/`. Remote models and textures are prohibited.

GLB components must dispose geometry, materials, and textures when their scene unmounts. Source assets are not bundled into the Tauri application.
