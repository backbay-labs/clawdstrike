#include "blst.h"
#include "ckzg.h"
#include <iostream>
#include <napi.h>
#include <sstream> // std::ostringstream
#include <stdio.h>
#include <string_view>

/**
 * Convert C_KZG_RET to a string representation for error messages.
 */
std::string from_c_kzg_ret(C_KZG_RET ret) {
    switch (ret) {
    case C_KZG_RET::C_KZG_OK:
        return "C_KZG_OK";
    case C_KZG_RET::C_KZG_BADARGS:
        return "C_KZG_BADARGS";
    case C_KZG_RET::C_KZG_ERROR:
        return "C_KZG_ERROR";
    case C_KZG_RET::C_KZG_MALLOC:
        return "C_KZG_MALLOC";
    default:
        std::ostringstream msg;
        msg << "UNKNOWN (" << ret << ")";
        return msg.str();
    }
}

/**
 * Structure containing information needed for the lifetime of the bindings
 * instance. It is not safe to use global static data with worker instances.
 * Native node addons are loaded as a dll's once no matter how many node
 * instances are using the library.  Each node instance will initialize an
 * instance of the bindings and workers share memory space.  In addition
 * the worker JS thread will be independent of the main JS thread. Global
 * statics are not thread safe and have the potential for initialization and
 * clean-up overwrites which results in segfault or undefined behavior.
 *
 * An instance of this struct will get created during initialization and it
 * will be available from the runtime. It can be retrieved via
 * `napi_get_instance_data` or `Napi::Env::GetInstanceData`.
 */
typedef struct {
    bool is_setup;
    KZGSettings settings;
} KzgAddonData;

/**
 * This cleanup function follows the `napi_finalize` interface and will be
 * called by the runtime when the exports object is garbage collected. Is
 * passed with napi_set_instance_data call when data is set.
 *
 * @remark This function should not be called, only the runtime should do
 *         the cleanup.
 *
 * @param[in] env  (unused)
 * @param[in] data Pointer KzgAddonData stored by the runtime
 * @param[in] hint (unused)
 */
void delete_kzg_addon_data(napi_env /*env*/, void *data, void * /*hint*/) {
    if (((KzgAddonData *)data)->is_setup) {
        free_trusted_setup(&((KzgAddonData *)data)->settings);
    }
    free(data);
}

/**
 * Get kzg_settings from bindings instance data
 *
 * Checks for:
 * - loadTrustedSetup has been run
 *
 * Designed to raise the correct javascript exception and return a
 * valid pointer to the calling context to avoid native stack-frame
 * unwinds.  Calling context can check for `nullptr` to see if an
 * exception was raised or a valid KZGSettings was returned.
 *
 * @param[in] env    Passed from calling context
 * @param[in] val    Napi::Value to validate and get pointer from
 *
 * @return - Pointer to the KZGSettings
 */
KZGSettings *get_kzg_settings(Napi::Env &env, const Napi::CallbackInfo &info) {
    KzgAddonData *data = env.GetInstanceData<KzgAddonData>();
    if (!data->is_setup) {
        Napi::Error::New(
            env,
            "Must run loadTrustedSetup before running any other c-kzg functions"
        )
            .ThrowAsJavaScriptException();
        return nullptr;
    }
    return &(data->settings);
}

/**
 * Checks for:
 * - arg is Uint8Array or Buffer (inherits from Uint8Array)
 * - underlying ArrayBuffer length is correct
 *
 * Internal function for argument validation. Prefer to use
 * the helpers below that already have the reinterpreted casts:
 * - get_blob
 * - get_bytes32
 * - get_bytes48
 *
 * Built to pass in a raw Napi::Value so it can be used like
 * `get_bytes(env, info[0])` or can also be used to pull props from
 * arrays like `get_bytes(env, passed_napi_array[2])`.
 *
 * Designed to raise the correct javascript exception and return a
 * valid pointer to the calling context to avoid native stack-frame
 * unwinds.  Calling context can check for `nullptr` to see if an
 * exception was raised or a valid pointer was returned from V8.
 *
 * @param[in] env    Passed from calling context
 * @param[in] val    Napi::Value to validate and get pointer from
 * @param[in] length Byte length to validate Uint8Array data against
 * @param[in] name   Name of prop being validated for error reporting
 *
 * @return - native pointer to first byte in ArrayBuffer
 */
inline uint8_t *get_bytes(
    const Napi::Env &env,
    const Napi::Value &val,
    size_t length,
    std::string_view name
) {
    if (!val.IsTypedArray() ||
        val.As<Napi::TypedArray>().TypedArrayType() != napi_uint8_array) {
        std::ostringstream msg;
        msg << "Expected " << name << " to be a Uint8Array";
        Napi::TypeError::New(env, msg.str()).ThrowAsJavaScriptException();
        return nullptr;
    }
    Napi::Uint8Array array = val.As<Napi::Uint8Array>();
    if (array.ByteLength() != length) {
        std::ostringstream msg;
        msg << "Expected " << name << " to be " << length << " bytes";
        Napi::TypeError::New(env, msg.str()).ThrowAsJavaScriptException();
        return nullptr;
    }
    return array.Data();
}
inline Blob *get_blob(const Napi::Env &env, const Napi::Value &val) {
    return reinterpret_cast<Blob *>(get_bytes(env, val, BYTES_PER_BLOB, "blob")
    );
}
inline Bytes32 *get_bytes32(
    const Napi::Env &env, const Napi::Value &val, std::string_view name
) {
    return reinterpret_cast<Bytes32 *>(
        get_bytes(env, val, BYTES_PER_FIELD_ELEMENT, name)
    );
}
inline Bytes48 *get_bytes48(
    const Napi::Env &env, const Napi::Value &val, std::string_view name
) {
    return reinterpret_cast<Bytes48 *>(
        get_bytes(env, val, BYTES_PER_COMMITMENT, name)
    );
}
inline Cell *get_cell(const Napi::Env &env, const Napi::Value &val) {
    return reinterpret_cast<Cell *>(get_bytes(env, val, BYTES_PER_CELL, "cell")
    );
}
inline uint64_t get_cell_index(const Napi::Env &env, const Napi::Value &val) {
    if (!val.IsNumber()) {
        Napi::TypeError::New(env, "cell index should be a number")
            .ThrowAsJavaScriptException();
        /* TODO: how will the caller know there was an error? */
        return 0;
    }
    double number = val.As<Napi::Number>().DoubleValue();
    return static_cast<uint64_t>(number);
}

Napi::Value LoadTrustedSetup(const Napi::CallbackInfo &info) {
    Napi::Env env = info.Env();

    // Check if the trusted setup is already loaded
    KzgAddonData *data = env.GetInstanceData<KzgAddonData>();
    if (data->is_setup) {
        Napi::Error::New(env, "Error trusted setup is already loaded")
            .ThrowAsJavaScriptException();
        return env.Undefined();
    }

    // Parse the precompute value
    uint64_t precompute = static_cast<uint64_t>(
        info[0].As<Napi::Number>().Int64Value()
    );

    // Open the trusted setup file
    std::string file_path = info[1].As<Napi::String>().Utf8Value();
    FILE *file_handle = fopen(file_path.c_str(), "r");
    if (file_handle == nullptr) {
        Napi::Error::New(env, "Error opening trusted setup file: " + file_path)
            .ThrowAsJavaScriptException();
        return env.Undefined();
    }

    // Load the trusted setup from that file
    C_KZG_RET ret = load_trusted_setup_file(
        &(data->settings), file_handle, precompute
    );
    // Close the trusted setup file
    fclose(file_handle);

    // Check that loading the trusted setup was successful
    if (ret != C_KZG_OK) {
        std::ostringstream msg;
        msg << "Error loading trusted setup file: " << from_c_kzg_ret(ret);
        Napi::Error::New(env, msg.str()).ThrowAsJavaScriptException();
        return env.Undefined();
    }

    data->is_setup = true;
    return env.Undefined();
}

/**
 * Convert a blob to a KZG commitment.
 *
 * @param[in] {Blob} blob - The blob representing the polynomial to be
 *                          committed to
 *
 * @return {KZGCommitment} - The resulting commitment
 *
 * @throws {TypeError} - For invalid arguments or failure of the native library
 */
Napi::Value BlobToKzgCommitment(const Napi::CallbackInfo &info) {
    Napi::Env env = info.Env();
    Blob *blob = get_blob(env, info[0]);
    if (blob == nullptr) {
        return env.Null();
    }
    KZGSettings *kzg_settings = get_kzg_settings(env, info);
    if (kzg_settings == nullptr) {
        return env.Null();
    }

    KZGCommitment commitment;
    C_KZG_RET ret = blob_to_kzg_commitment(&commitment, blob, kzg_settings);
    if (ret != C_KZG_OK) {
        std::ostringstream msg;
        msg << "Failed to convert blob to commitment: " << from_c_kzg_ret(ret);
        Napi::Error::New(env, msg.str()).ThrowAsJavaScriptException();
        return env.Undefined();
    }

    return Napi::Buffer<uint8_t>::Copy(
        env, reinterpret_cast<uint8_t *>(&commitment), BYTES_PER_COMMITMENT
    );
}

/**
 * Compute KZG proof for polynomial in Lagrange form at position z.
 *
 * @param[in] {Blob}    blob - The blob (polynomial) to generate a proof for
 * @param[in] {Bytes32} zBytes - The generator z-value for the evaluation points
 *
 * @return {ProofResult} - Tuple containing the resulting proof and evaluation
 *                         of the polynomial at the evaluation point z
 *
 * @throws {TypeError} - for invalid arguments or failure of the native library
 */
Napi::Value ComputeKzgProof(const Napi::CallbackInfo &info) {
    Napi::Env env = info.Env();
    Blob *blob = get_blob(env, info[0]);
    if (blob == nullptr) {
        return env.Null();
    }
    Bytes32 *z_bytes = get_bytes32(env, info[1], "zBytes");
    if (z_bytes == nullptr) {
        return env.Null();
    }
    KZGSettings *kzg_settings = get_kzg_settings(env, info);
    if (kzg_settings == nullptr) {
        return env.Null();
    }

    KZGProof proof;
    Bytes32 y_out;
    C_KZG_RET ret = compute_kzg_proof(
        &proof, &y_out, blob, z_bytes, kzg_settings
    );

    if (ret != C_KZG_OK) {
        std::ostringstream msg;
        msg << "Failed to compute proof: " << from_c_kzg_ret(ret);
        Napi::Error::New(env, msg.str()).ThrowAsJavaScriptException();
        return env.Undefined();
    }

    Napi::Array tuple = Napi::Array::New(env, 2);
    tuple[(uint32_t)0] = Napi::Buffer<uint8_t>::Copy(
        env, reinterpret_cast<uint8_t *>(&proof), BYTES_PER_PROOF
    );
    tuple[(uint32_t)1] = Napi::Buffer<uint8_t>::Copy(
        env, reinterpret_cast<uint8_t *>(&y_out), BYTES_PER_FIELD_ELEMENT
    );
    return tuple;
}

/**
 * Given a blob, return the KZG proof that is used to verify it against the
 * commitment.
 *
 * @param[in] {Blob}    blob - The blob (polynomial) to generate a proof for
 * @param[in] {Bytes48} commitmentBytes - Commitment to verify
 *
 * @return {KZGProof} - The resulting proof
 *
 * @throws {TypeError} - for invalid arguments or failure of the native library
 */
Napi::Value ComputeBlobKzgProof(const Napi::CallbackInfo &info) {
    Napi::Env env = info.Env();
    Blob *blob = get_blob(env, info[0]);
    if (blob == nullptr) {
        return env.Null();
    }
    Bytes48 *commitment_bytes = get_bytes48(env, info[1], "commitmentBytes");
    if (commitment_bytes == nullptr) {
        return env.Null();
    }
    KZGSettings *kzg_settings = get_kzg_settings(env, info);
    if (kzg_settings == nullptr) {
        return env.Null();
    }

    KZGProof proof;
    C_KZG_RET ret = compute_blob_kzg_proof(
        &proof, blob, commitment_bytes, kzg_settings
    );

    if (ret != C_KZG_OK) {
        std::ostringstream msg;
        msg << "Error in computeBlobKzgProof: " << from_c_kzg_ret(ret);
        Napi::Error::New(env, msg.str()).ThrowAsJavaScriptException();
        return env.Undefined();
    }

    return Napi::Buffer<uint8_t>::Copy(
        env, reinterpret_cast<uint8_t *>(&proof), BYTES_PER_PROOF
    );
}

/**
 * Verify a KZG poof claiming that `p(z) == y`.
 *
 * @param[in] {Bytes48} commitmentBytes - The serialized commitment
 * corresponding to polynomial p(x)
 * @param[in] {Bytes32} zBytes - The serialized evaluation point
 * @param[in] {Bytes32} yBytes - The serialized claimed evaluation result
 * @param[in] {Bytes48} proofBytes - The serialized KZG proof
 *
 * @return {boolean} - true/false depending on proof validity
 *
 * @throws {TypeError} - for invalid arguments or failure of the native library
 */
Napi::Value VerifyKzgProof(const Napi::CallbackInfo &info) {
    Napi::Env env = info.Env();
    Bytes48 *commitment_bytes = get_bytes48(env, info[0], "commitmentBytes");
    if (commitment_bytes == nullptr) {
        return env.Null();
    }
    Bytes32 *z_bytes = get_bytes32(env, info[1], "zBytes");
    if (z_bytes == nullptr) {
        return env.Null();
    }
    Bytes32 *y_bytes = get_bytes32(env, info[2], "yBytes");
    if (y_bytes == nullptr) {
        return env.Null();
    }
    Bytes48 *proof_bytes = get_bytes48(env, info[3], "proofBytes");
    if (proof_bytes == nullptr) {
        return env.Null();
    }
    KZGSettings *kzg_settings = get_kzg_settings(env, info);
    if (kzg_settings == nullptr) {
        return env.Null();
    }

    bool out;
    C_KZG_RET ret = verify_kzg_proof(
        &out, commitment_bytes, z_bytes, y_bytes, proof_bytes, kzg_settings
    );

    if (ret != C_KZG_OK) {
        std::ostringstream msg;
        msg << "Failed to verify KZG proof: " << from_c_kzg_ret(ret);
        Napi::Error::New(env, msg.str()).ThrowAsJavaScriptException();
        return env.Undefined();
    }

    return Napi::Boolean::New(env, out);
}

/**
 * Given a blob and its proof, verify that it corresponds to the provided
 * commitment.
 *
 * @param[in] {Blob}    blob - The serialized blob to verify
 * @param[in] {Bytes48} commitmentBytes - The serialized commitment to verify
 * @param[in] {Bytes48} proofBytes - The serialized KZG proof for verification
 *
 * @return {boolean} - true/false depending on proof validity
 *
 * @throws {TypeError} - for invalid arguments or failure of the native library
 */
Napi::Value VerifyBlobKzgProof(const Napi::CallbackInfo &info) {
    Napi::Env env = info.Env();
    Blob *blob_bytes = get_blob(env, info[0]);
    if (blob_bytes == nullptr) {
        return env.Null();
    }
    Bytes48 *commitment_bytes = get_bytes48(env, info[1], "commitmentBytes");
    if (commitment_bytes == nullptr) {
        return env.Null();
    }
    Bytes48 *proof_bytes = get_bytes48(env, info[2], "proofBytes");
    if (proof_bytes == nullptr) {
        return env.Null();
    }
    KZGSettings *kzg_settings = get_kzg_settings(env, info);
    if (kzg_settings == nullptr) {
        return env.Null();
    }

    bool out;
    C_KZG_RET ret = verify_blob_kzg_proof(
        &out, blob_bytes, commitment_bytes, proof_bytes, kzg_settings
    );

    if (ret != C_KZG_OK) {
        std::ostringstream msg;
        msg << "Error in verifyBlobKzgProof: " << from_c_kzg_ret(ret);
        Napi::Error::New(env, msg.str()).ThrowAsJavaScriptException();
        return env.Undefined();
    }

    return Napi::Boolean::New(env, out);
}

/**
 * Given an array of blobs and their proofs, verify that they corresponds to
 * their provided commitment.
 *
 * @remark blobs[0] relates to commitmentBytes[0] and proofBytes[0]
 *
 * @param[in] {Blob}    blobs - An array of serialized blobs to verify
 * @param[in] {Bytes48} commitmentBytes - An array of serialized commitments to
 *                                        verify
 * @param[in] {Bytes48} proofBytes - An array of serialized KZG proofs for
 *                                   verification
 *
 * @return {boolean} - true/false depending on batch validity
 *
 * @throws {TypeError} - for invalid arguments or failure of the native library
 */
Napi::Value VerifyBlobKzgProofBatch(const Napi::CallbackInfo &info) {
    Napi::Env env = info.Env();
    C_KZG_RET ret;
    Blob *blobs = NULL;
    Bytes48 *commitments = NULL;
    Bytes48 *proofs = NULL;
    Napi::Value result = env.Null();
    if (!(info[0].IsArray() && info[1].IsArray() && info[2].IsArray())) {
        Napi::Error::New(
            env, "Blobs, commitments, and proofs must all be arrays"
        )
            .ThrowAsJavaScriptException();
        return result;
    }
    Napi::Array blobs_param = info[0].As<Napi::Array>();
    Napi::Array commitments_param = info[1].As<Napi::Array>();
    Napi::Array proofs_param = info[2].As<Napi::Array>();
    KZGSettings *kzg_settings = get_kzg_settings(env, info);
    if (kzg_settings == nullptr) {
        return env.Null();
    }
    uint32_t count = blobs_param.Length();
    if (count != commitments_param.Length() || count != proofs_param.Length()) {
        Napi::Error::New(
            env, "Requires equal number of blobs/commitments/proofs"
        )
            .ThrowAsJavaScriptException();
        return result;
    }
    blobs = (Blob *)calloc(count, sizeof(Blob));
    if (blobs == nullptr) {
        Napi::Error::New(env, "Error while allocating memory for blobs")
            .ThrowAsJavaScriptException();
        goto out;
    }
    commitments = (Bytes48 *)calloc(count, sizeof(Bytes48));
    if (commitments == nullptr) {
        Napi::Error::New(env, "Error while allocating memory for commitments")
            .ThrowAsJavaScriptException();
        goto out;
    }
    proofs = (Bytes48 *)calloc(count, sizeof(Bytes48));
    if (proofs == nullptr) {
        Napi::Error::New(env, "Error while allocating memory for proofs")
            .ThrowAsJavaScriptException();
        goto out;
    }

    for (uint32_t index = 0; index < count; index++) {
        // add HandleScope here to release reference to temp values
        // after each iteration since data is being memcpy
        Napi::HandleScope scope{env};
        Blob *blob = get_blob(env, blobs_param[index]);
        if (blob == nullptr) {
            goto out;
        }
        memcpy(&blobs[index], blob, BYTES_PER_BLOB);
        Bytes48 *commitment = get_bytes48(
            env, commitments_param[index], "commitmentBytes"
        );
        if (commitment == nullptr) {
            goto out;
        }
        memcpy(&commitments[index], commitment, BYTES_PER_COMMITMENT);
        Bytes48 *proof = get_bytes48(env, proofs_param[index], "proofBytes");
        if (proof == nullptr) {
            goto out;
        }
        memcpy(&proofs[index], proof, BYTES_PER_PROOF);
    }

    bool out;
    ret = verify_blob_kzg_proof_batch(
        &out, blobs, commitments, proofs, count, kzg_settings
    );

    if (ret != C_KZG_OK) {
        std::ostringstream msg;
        msg << "Error in verifyBlobKzgProofBatch: " << from_c_kzg_ret(ret);
        Napi::Error::New(env, msg.str()).ThrowAsJavaScriptException();
        goto out;
    }

    result = Napi::Boolean::New(env, out);

out:
    free(blobs);
    free(commitments);
    free(proofs);
    return result;
}

/**
 * Get the cells for a given blob.
 *
 * @param[in] {Blob}    blob - the blob to get cells for
 *
 * @return {Cell[]} - An array of cells
 *
 * @throws {Error} - Failure to allocate or compute cells
 */
Napi::Value ComputeCells(const Napi::CallbackInfo &info) {
    Napi::Env env = info.Env();
    Napi::Value result = env.Null();
    Blob *blob = get_blob(env, info[0]);
    if (blob == nullptr) {
        return env.Null();
    }
    KZGSettings *kzg_settings = get_kzg_settings(env, info);
    if (kzg_settings == nullptr) {
        return env.Null();
    }

    C_KZG_RET ret;
    Cell *cells = NULL;
    Napi::Array cellArray;

    cells = (Cell *)calloc(CELLS_PER_EXT_BLOB, BYTES_PER_CELL);
    if (cells == nullptr) {
        std::ostringstream msg;
        msg << "Failed to allocate cells in computeCellsAndKzgProofs";
        Napi::Error::New(env, msg.str()).ThrowAsJavaScriptException();
        goto out;
    }

    ret = compute_cells_and_kzg_proofs(cells, NULL, blob, kzg_settings);
    if (ret != C_KZG_OK) {
        std::ostringstream msg;
        msg << "Error in computeCellsAndKzgProofs: " << from_c_kzg_ret(ret);
        Napi::Error::New(env, msg.str()).ThrowAsJavaScriptException();
        goto out;
    }

    cellArray = Napi::Array::New(env, CELLS_PER_EXT_BLOB);
    for (size_t i = 0; i < CELLS_PER_EXT_BLOB; i++) {
        cellArray.Set(
            i,
            Napi::Buffer<uint8_t>::Copy(
                env, reinterpret_cast<uint8_t *>(&cells[i]), BYTES_PER_CELL
            )
        );
    }

    result = cellArray;

out:
    free(cells);
    return result;
}

/**
 * Get the cells and proofs for a given blob.
 *
 * @param[in] {Blob}    blob - the blob to get cells/proofs for
 *
 * @return {[Cell[], KZGProof[]]} - A tuple of cells and proofs
 *
 * @throws {Error} - Failure to allocate or compute cells and proofs
 */
Napi::Value ComputeCellsAndKzgProofs(const Napi::CallbackInfo &info) {
    Napi::Env env = info.Env();
    Napi::Value result = env.Null();
    Blob *blob = get_blob(env, info[0]);
    if (blob == nullptr) {
        return env.Null();
    }
    KZGSettings *kzg_settings = get_kzg_settings(env, info);
    if (kzg_settings == nullptr) {
        return env.Null();
    }

    C_KZG_RET ret;
    Cell *cells = NULL;
    KZGProof *proofs = NULL;
    Napi::Array tuple;
    Napi::Array cellArray;
    Napi::Array proofArray;

    cells = (Cell *)calloc(CELLS_PER_EXT_BLOB, BYTES_PER_CELL);
    if (cells == nullptr) {
        std::ostringstream msg;
        msg << "Failed to allocate cells in computeCellsAndKzgProofs";
        Napi::Error::New(env, msg.str()).ThrowAsJavaScriptException();
        goto out;
    }

    proofs = (KZGProof *)calloc(CELLS_PER_EXT_BLOB, BYTES_PER_PROOF);
    if (proofs == nullptr) {
        std::ostringstream msg;
        msg << "Failed to allocate proofs in computeCellsAndKzgProofs";
        Napi::Error::New(env, msg.str()).ThrowAsJavaScriptException();
        goto out;
    }

    ret = compute_cells_and_kzg_proofs(cells, proofs, blob, kzg_settings);
    if (ret != C_KZG_OK) {
        std::ostringstream msg;
        msg << "Error in computeCellsAndKzgProofs: " << from_c_kzg_ret(ret);
        Napi::Error::New(env, msg.str()).ThrowAsJavaScriptException();
        goto out;
    }

    cellArray = Napi::Array::New(env, CELLS_PER_EXT_BLOB);
    proofArray = Napi::Array::New(env, CELLS_PER_EXT_BLOB);
    for (size_t i = 0; i < CELLS_PER_EXT_BLOB; i++) {
        cellArray.Set(
            i,
            Napi::Buffer<uint8_t>::Copy(
                env, reinterpret_cast<uint8_t *>(&cells[i]), BYTES_PER_CELL
            )
        );
        proofArray.Set(
            i,
            Napi::Buffer<uint8_t>::Copy(
                env, reinterpret_cast<uint8_t *>(&proofs[i]), BYTES_PER_PROOF
            )
        );
    }

    tuple = Napi::Array::New(env, 2);
    tuple[(uint32_t)0] = cellArray;
    tuple[(uint32_t)1] = proofArray;
    result = tuple;

out:
    free(cells);
    free(proofs);
    return result;
}

/**
 * Given at least 50% of cells, reconstruct the missing cells/proofs.
 *
 * @param[in] {number[]}  cellIndices - The identifiers for the cells you have
 * @param[in] {Cell[]}    cells - The cells you have
 *
 * @return {[Cell[], KZGProof[]]} - A tuple of cells and proofs
 *
 * @throws {Error} - Invalid input, failure to allocate or error recovering
 * cells and proofs
 */
Napi::Value RecoverCellsAndKzgProofs(const Napi::CallbackInfo &info) {
    C_KZG_RET ret;
    uint64_t *cell_indices = NULL;
    Cell *cells = NULL;
    Cell *recovered_cells = NULL;
    KZGProof *recovered_proofs = NULL;
    Napi::Array tuple;
    Napi::Array cellArray;
    Napi::Array proofArray;
    uint64_t num_cells;

    Napi::Env env = info.Env();
    Napi::Value result = env.Null();
    if (!info[0].IsArray()) {
        Napi::Error::New(env, "CellIndices must be an array")
            .ThrowAsJavaScriptException();
        return result;
    }
    if (!info[1].IsArray()) {
        Napi::Error::New(env, "Cells must be an array")
            .ThrowAsJavaScriptException();
        return result;
    }
    KZGSettings *kzg_settings = get_kzg_settings(env, info);
    if (kzg_settings == nullptr) {
        return env.Null();
    }

    Napi::Array cell_indices_param = info[0].As<Napi::Array>();
    Napi::Array cells_param = info[1].As<Napi::Array>();

    if (cell_indices_param.Length() != cells_param.Length()) {
        Napi::Error::New(
            env, "There must equal lengths of cellIndices and cells"
        )
            .ThrowAsJavaScriptException();
        goto out;
    }

    num_cells = cells_param.Length();
    cell_indices = (uint64_t *)calloc(num_cells, sizeof(uint64_t));
    if (cell_indices == nullptr) {
        Napi::Error::New(env, "Error while allocating memory for cell_indices")
            .ThrowAsJavaScriptException();
        goto out;
    }
    cells = (Cell *)calloc(num_cells, BYTES_PER_CELL);
    if (cells == nullptr) {
        Napi::Error::New(env, "Error while allocating memory for cells")
            .ThrowAsJavaScriptException();
        goto out;
    }
    recovered_cells = (Cell *)calloc(CELLS_PER_EXT_BLOB, BYTES_PER_CELL);
    if (recovered_cells == nullptr) {
        Napi::Error::New(
            env, "Error while allocating memory for recovered cells"
        )
            .ThrowAsJavaScriptException();
        goto out;
    }
    recovered_proofs = (KZGProof *)calloc(CELLS_PER_EXT_BLOB, BYTES_PER_PROOF);
    if (recovered_proofs == nullptr) {
        Napi::Error::New(
            env, "Error while allocating memory for recovered proofs"
        )
            .ThrowAsJavaScriptException();
        goto out;
    }

    for (uint64_t i = 0; i < num_cells; i++) {
        // add HandleScope here to release reference to temp values
        // after each iteration since data is being memcpy
        Napi::HandleScope scope{env};

        cell_indices[i] = get_cell_index(env, cell_indices_param[i]);
        Cell *cell = get_cell(env, cells_param[i]);
        if (cell == nullptr) {
            goto out;
        }
        memcpy(&cells[i], cell, BYTES_PER_CELL);
    }

    ret = recover_cells_and_kzg_proofs(
        recovered_cells,
        recovered_proofs,
        cell_indices,
        cells,
        num_cells,
        kzg_settings
    );
    if (ret != C_KZG_OK) {
        std::ostringstream msg;
        msg << "Error in recoverCellsAndKzgProofs: " << from_c_kzg_ret(ret);
        Napi::Error::New(env, msg.str()).ThrowAsJavaScriptException();
        goto out;
    }

    cellArray = Napi::Array::New(env, CELLS_PER_EXT_BLOB);
    proofArray = Napi::Array::New(env, CELLS_PER_EXT_BLOB);
    for (size_t i = 0; i < CELLS_PER_EXT_BLOB; i++) {
        cellArray.Set(
            i,
            Napi::Buffer<uint8_t>::Copy(
                env,
                reinterpret_cast<uint8_t *>(&recovered_cells[i]),
                BYTES_PER_CELL
            )
        );
        proofArray.Set(
            i,
            Napi::Buffer<uint8_t>::Copy(
                env,
                reinterpret_cast<uint8_t *>(&recovered_proofs[i]),
                BYTES_PER_PROOF
            )
        );
    }

    tuple = Napi::Array::New(env, 2);
    tuple[(uint32_t)0] = cellArray;
    tuple[(uint32_t)1] = proofArray;
    result = tuple;

out:
    free(cell_indices);
    free(cells);
    free(recovered_cells);
    free(recovered_proofs);
    return result;
}

/**
 * Verify that multiple cells' proofs are valid.
 *
 * @param[in] {Bytes48[]} commitmentsBytes - The commitments for each cell
 * @param[in] {number[]}  cellIndices - The cell index for each cell
 * @param[in] {Cell[]}    cells - The cells to verify
 * @param[in] {Bytes48[]} proofsBytes - The proof for each cell
 *
 * @return {boolean} - True if the cells are valid with respect to the given
 * commitments
 *
 * @throws {Error} - Invalid input, failure to allocate memory, or errors
 * verifying batch
 */
Napi::Value VerifyCellKzgProofBatch(const Napi::CallbackInfo &info) {
    Napi::Env env = info.Env();
    Napi::Value result = env.Null();
    if (!(info[0].IsArray() && info[1].IsArray() && info[2].IsArray() &&
          info[3].IsArray())) {
        Napi::Error::New(
            env, "commitments, cell_indices, cells, and proofs must be arrays"
        )
            .ThrowAsJavaScriptException();
        return result;
    }
    Napi::Array commitments_param = info[0].As<Napi::Array>();
    Napi::Array cell_indices_param = info[1].As<Napi::Array>();
    Napi::Array cells_param = info[2].As<Napi::Array>();
    Napi::Array proofs_param = info[3].As<Napi::Array>();
    KZGSettings *kzg_settings = get_kzg_settings(env, info);
    if (kzg_settings == nullptr) {
        return env.Null();
    }

    C_KZG_RET ret;
    bool out;
    Bytes48 *commitments = NULL;
    uint64_t *cell_indices = NULL;
    Cell *cells = NULL;
    Bytes48 *proofs = NULL;

    uint64_t num_cells = cells_param.Length();

    if (commitments_param.Length() != num_cells ||
        cell_indices_param.Length() != num_cells ||
        proofs_param.Length() != num_cells) {
        Napi::Error::New(
            env,
            "Must have equal lengths for commitments, cell_indices, cells, "
            "and proofs"
        )
            .ThrowAsJavaScriptException();
        goto out;
    }

    commitments = (Bytes48 *
    )calloc(commitments_param.Length(), sizeof(Bytes48));
    if (commitments == nullptr) {
        Napi::Error::New(env, "Error while allocating memory for commitments")
            .ThrowAsJavaScriptException();
        goto out;
    }
    cell_indices = (uint64_t *
    )calloc(cell_indices_param.Length(), sizeof(uint64_t));
    if (cell_indices == nullptr) {
        Napi::Error::New(env, "Error while allocating memory for cell_indices")
            .ThrowAsJavaScriptException();
        goto out;
    }
    cells = (Cell *)calloc(cells_param.Length(), sizeof(Cell));
    if (cells == nullptr) {
        Napi::Error::New(env, "Error while allocating memory for cells")
            .ThrowAsJavaScriptException();
        goto out;
    }
    proofs = (Bytes48 *)calloc(proofs_param.Length(), sizeof(Bytes48));
    if (proofs == nullptr) {
        Napi::Error::New(env, "Error while allocating memory for proofs")
            .ThrowAsJavaScriptException();
        goto out;
    }

    for (uint64_t i = 0; i < num_cells; i++) {
        // add HandleScope here to release reference to temp values
        // after each iteration since data is being memcpy
        Napi::HandleScope scope{env};
        Bytes48 *commitment = get_bytes48(
            env, commitments_param[i], "commitmentBytes"
        );
        if (commitment == nullptr) {
            goto out;
        }
        memcpy(&commitments[i], commitment, BYTES_PER_COMMITMENT);
        cell_indices[i] = get_cell_index(env, cell_indices_param[i]);
        Cell *cell = get_cell(env, cells_param[i]);
        if (cell == nullptr) {
            goto out;
        }
        memcpy(&cells[i], cell, BYTES_PER_CELL);
        Bytes48 *proof = get_bytes48(env, proofs_param[i], "proofBytes");
        if (proof == nullptr) {
            goto out;
        }
        memcpy(&proofs[i], proof, BYTES_PER_PROOF);
    }

    ret = verify_cell_kzg_proof_batch(
        &out, commitments, cell_indices, cells, proofs, num_cells, kzg_settings
    );
    if (ret != C_KZG_OK) {
        std::ostringstream msg;
        msg << "Error in verifyCellKzgProofBatch: " << from_c_kzg_ret(ret);
        Napi::Error::New(env, msg.str()).ThrowAsJavaScriptException();
        goto out;
    }

    result = Napi::Boolean::New(env, out);

out:
    free(commitments);
    free(cell_indices);
    free(cells);
    free(proofs);

    return result;
}

Napi::Object Init(Napi::Env env, Napi::Object exports) {
    KzgAddonData *data = (KzgAddonData *)malloc(sizeof(KzgAddonData));
    if (data == nullptr) {
        Napi::Error::New(env, "Error allocating memory for kzg setup handle")
            .ThrowAsJavaScriptException();
        return exports;
    }
    data->is_setup = false;
    napi_status status = napi_set_instance_data(
        env, data, delete_kzg_addon_data, NULL
    );
    if (status != napi_ok) {
        Napi::Error::New(env, "Error setting kzg bindings instance data")
            .ThrowAsJavaScriptException();
        return exports;
    }

    // Functions
    exports["loadTrustedSetup"] = Napi::Function::New(
        env, LoadTrustedSetup, "setup"
    );
    exports["blobToKzgCommitment"] = Napi::Function::New(
        env, BlobToKzgCommitment, "blobToKzgCommitment"
    );
    exports["computeKzgProof"] = Napi::Function::New(
        env, ComputeKzgProof, "computeKzgProof"
    );
    exports["computeBlobKzgProof"] = Napi::Function::New(
        env, ComputeBlobKzgProof, "computeBlobKzgProof"
    );
    exports["verifyKzgProof"] = Napi::Function::New(
        env, VerifyKzgProof, "verifyKzgProof"
    );
    exports["verifyBlobKzgProof"] = Napi::Function::New(
        env, VerifyBlobKzgProof, "verifyBlobKzgProof"
    );
    exports["verifyBlobKzgProofBatch"] = Napi::Function::New(
        env, VerifyBlobKzgProofBatch, "verifyBlobKzgProofBatch"
    );
    exports["computeCells"] = Napi::Function::New(
        env, ComputeCells, "computeCells"
    );
    exports["computeCellsAndKzgProofs"] = Napi::Function::New(
        env, ComputeCellsAndKzgProofs, "computeCellsAndKzgProofs"
    );
    exports["recoverCellsAndKzgProofs"] = Napi::Function::New(
        env, RecoverCellsAndKzgProofs, "recoverCellsAndKzgProofs"
    );
    exports["verifyCellKzgProofBatch"] = Napi::Function::New(
        env, VerifyCellKzgProofBatch, "verifyCellKzgProofBatch"
    );

    // Constants
    exports["BYTES_PER_BLOB"] = Napi::Number::New(env, BYTES_PER_BLOB);
    exports["BYTES_PER_COMMITMENT"] = Napi::Number::New(
        env, BYTES_PER_COMMITMENT
    );
    exports["BYTES_PER_FIELD_ELEMENT"] = Napi::Number::New(
        env, BYTES_PER_FIELD_ELEMENT
    );
    exports["BYTES_PER_PROOF"] = Napi::Number::New(env, BYTES_PER_PROOF);
    exports["BYTES_PER_CELL"] = Napi::Number::New(env, BYTES_PER_CELL);
    exports["FIELD_ELEMENTS_PER_BLOB"] = Napi::Number::New(
        env, FIELD_ELEMENTS_PER_BLOB
    );
    exports["FIELD_ELEMENTS_PER_CELL"] = Napi::Number::New(
        env, FIELD_ELEMENTS_PER_CELL
    );
    exports["CELLS_PER_EXT_BLOB"] = Napi::Number::New(env, CELLS_PER_EXT_BLOB);

    return exports;
}

NODE_API_MODULE(addon, Init)
