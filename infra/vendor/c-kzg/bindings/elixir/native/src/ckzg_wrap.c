#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <erl_nif.h>

#include "ckzg.h"

typedef struct {
    ERL_NIF_TERM ok;
    ERL_NIF_TERM error;
    ERL_NIF_TERM a_true;
    ERL_NIF_TERM a_false;
    ERL_NIF_TERM kzg_badargs;
    ERL_NIF_TERM kzg_error;
    ERL_NIF_TERM kzg_malloc;
    ERL_NIF_TERM kzg_unknown_error;
    ERL_NIF_TERM incorrect_arg_count;
    ERL_NIF_TERM invalid_precompute_arg;
    ERL_NIF_TERM out_of_memory;
    ERL_NIF_TERM bad_file_string_arg;
    ERL_NIF_TERM failed_to_open_file;
    ERL_NIF_TERM failed_alloc_settings_resource;
    ERL_NIF_TERM blob_not_binary;
    ERL_NIF_TERM invalid_blob_length;
    ERL_NIF_TERM z_not_binary;
    ERL_NIF_TERM invalid_z_length;
    ERL_NIF_TERM y_not_binary;
    ERL_NIF_TERM invalid_y_length;
    ERL_NIF_TERM commitment_not_binary;
    ERL_NIF_TERM invalid_commitment_length;
    ERL_NIF_TERM proof_not_binary;
    ERL_NIF_TERM invalid_proof_length;
    ERL_NIF_TERM failed_get_settings_resource;
    ERL_NIF_TERM expected_same_array_size;
    ERL_NIF_TERM cell_indices_not_list;
    ERL_NIF_TERM cells_not_list;
    ERL_NIF_TERM cell_indices_value_not_uint64;
    ERL_NIF_TERM cells_value_not_binary;
    ERL_NIF_TERM invalid_cell_length;
    ERL_NIF_TERM commitments_not_list;
    ERL_NIF_TERM proofs_not_list;
} ckzg_atoms_t;

ErlNifResourceType *KZGSETTINGS_RES_TYPE;
static ckzg_atoms_t ckzg_atoms;

#define MAKE_ATOM_2(item, name) ckzg_atoms.item = enif_make_atom(env, #name)
#define MAKE_ATOM(name) MAKE_ATOM_2(name, name)

static inline ERL_NIF_TERM make_error(ErlNifEnv *env, ERL_NIF_TERM error_atom) {
    return enif_make_tuple2(env, ckzg_atoms.error, error_atom);
}

static inline ERL_NIF_TERM make_success(ErlNifEnv *env, ERL_NIF_TERM ret) {
    return enif_make_tuple2(env, ckzg_atoms.ok, ret);
}

static inline ERL_NIF_TERM make_kzg_error(ErlNifEnv *env, C_KZG_RET ret) {
    ERL_NIF_TERM atom;
    switch (ret) {
    case C_KZG_OK:
        atom = ckzg_atoms.ok;
        break;
    case C_KZG_BADARGS:
        atom = ckzg_atoms.kzg_badargs;
        break;
    case C_KZG_ERROR:
        atom = ckzg_atoms.kzg_error;
        break;
    case C_KZG_MALLOC:
        atom = ckzg_atoms.kzg_malloc;
        break;
    default:
        atom = ckzg_atoms.kzg_unknown_error;
        break;
    }

    return make_error(env, atom);
}

static void KZGSettings_destructor(ErlNifEnv *env, void *res) {
    // Unused.
    (void)env;

    KZGSettings *settings = (KZGSettings *)res;
    free_trusted_setup(settings);
}

// NIF entrypoint
static int load(ErlNifEnv *env, void **priv_data, ERL_NIF_TERM load_info) {
    // Unused.
    (void)priv_data;
    (void)load_info;

    KZGSETTINGS_RES_TYPE = enif_open_resource_type(
        env,
        NULL,
        "ckzg_settings",
        KZGSettings_destructor,
        ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER,
        NULL
    );
    if (KZGSETTINGS_RES_TYPE == NULL) return -1;

    MAKE_ATOM(ok);
    MAKE_ATOM(error);
    MAKE_ATOM_2(a_true, true);
    MAKE_ATOM_2(a_false, false);
    MAKE_ATOM(kzg_badargs);
    MAKE_ATOM(kzg_error);
    MAKE_ATOM(kzg_malloc);
    MAKE_ATOM(kzg_unknown_error);
    MAKE_ATOM(incorrect_arg_count);
    MAKE_ATOM(invalid_precompute_arg);
    MAKE_ATOM(out_of_memory);
    MAKE_ATOM(bad_file_string_arg);
    MAKE_ATOM(failed_to_open_file);
    MAKE_ATOM(failed_alloc_settings_resource);
    MAKE_ATOM(blob_not_binary);
    MAKE_ATOM(invalid_blob_length);
    MAKE_ATOM(z_not_binary);
    MAKE_ATOM(invalid_z_length);
    MAKE_ATOM(y_not_binary);
    MAKE_ATOM(invalid_y_length);
    MAKE_ATOM(commitment_not_binary);
    MAKE_ATOM(invalid_commitment_length);
    MAKE_ATOM(proof_not_binary);
    MAKE_ATOM(invalid_proof_length);
    MAKE_ATOM(failed_get_settings_resource);
    MAKE_ATOM(expected_same_array_size);
    MAKE_ATOM(cell_indices_not_list);
    MAKE_ATOM(cells_not_list);
    MAKE_ATOM(cell_indices_value_not_uint64);
    MAKE_ATOM(cells_value_not_binary);
    MAKE_ATOM(invalid_cell_length);
    MAKE_ATOM(commitments_not_list);
    MAKE_ATOM(proofs_not_list);

    return 0;
}

static ERL_NIF_TERM load_trusted_setup_nif(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    if (argc != 2) return make_error(env, ckzg_atoms.incorrect_arg_count);

    ErlNifBinary file;
    if (!enif_inspect_binary(env, argv[0], &file)) {
        return make_error(env, ckzg_atoms.bad_file_string_arg);
    }

    unsigned long precompute;
    if (!enif_get_ulong(env, argv[1], &precompute))
        return make_error(env, ckzg_atoms.invalid_precompute_arg);

    char *name = enif_alloc(file.size + 1);
    memcpy(name, file.data, file.size);
    name[file.size] = '\0';

    FILE *fp = fopen(name, "r");
    enif_free(name);

    if (fp == NULL) return make_error(env, ckzg_atoms.failed_to_open_file);

    KZGSettings *settings = enif_alloc_resource(KZGSETTINGS_RES_TYPE, sizeof(KZGSettings));
    if (settings == NULL) {
        fclose(fp);
        return make_error(env, ckzg_atoms.failed_alloc_settings_resource);
    }

    C_KZG_RET ret = load_trusted_setup_file(settings, fp, precompute);
    fclose(fp);

    if (ret != C_KZG_OK) {
        enif_release_resource(settings);
        return make_kzg_error(env, ret);
    }

    ERL_NIF_TERM settings_term = enif_make_resource(env, settings);
    enif_release_resource(settings);

    return make_success(env, settings_term);
}

static ERL_NIF_TERM blob_to_kzg_commitment_nif(
    ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]
) {
    if (argc != 2) return make_error(env, ckzg_atoms.incorrect_arg_count);

    ErlNifBinary blob;
    if (!enif_inspect_binary(env, argv[0], &blob))
        return make_error(env, ckzg_atoms.blob_not_binary);

    if (blob.size != BYTES_PER_BLOB) return make_error(env, ckzg_atoms.invalid_blob_length);

    KZGSettings *settings;
    if (!enif_get_resource(env, argv[1], KZGSETTINGS_RES_TYPE, (void **)&settings))
        return make_error(env, ckzg_atoms.failed_get_settings_resource);

    ERL_NIF_TERM commitment_term;
    unsigned char *commitment = enif_make_new_binary(env, BYTES_PER_COMMITMENT, &commitment_term);
    if (commitment == NULL) return make_error(env, ckzg_atoms.out_of_memory);

    C_KZG_RET ret = blob_to_kzg_commitment(
        (KZGCommitment *)commitment, (const Blob *)blob.data, settings
    );
    if (ret != C_KZG_OK) return make_kzg_error(env, ret);

    return make_success(env, commitment_term);
}

static ERL_NIF_TERM compute_kzg_proof_nif(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    if (argc != 3) return make_error(env, ckzg_atoms.incorrect_arg_count);

    ErlNifBinary blob;
    if (!enif_inspect_binary(env, argv[0], &blob))
        return make_error(env, ckzg_atoms.blob_not_binary);

    if (blob.size != BYTES_PER_BLOB) return make_error(env, ckzg_atoms.invalid_blob_length);

    ErlNifBinary z;
    if (!enif_inspect_binary(env, argv[1], &z)) return make_error(env, ckzg_atoms.z_not_binary);

    if (z.size != BYTES_PER_FIELD_ELEMENT) return make_error(env, ckzg_atoms.invalid_z_length);

    KZGSettings *settings;
    if (!enif_get_resource(env, argv[2], KZGSETTINGS_RES_TYPE, (void **)&settings))
        return make_error(env, ckzg_atoms.failed_get_settings_resource);

    ERL_NIF_TERM y_term;
    unsigned char *y_bytes = enif_make_new_binary(env, sizeof(Bytes32), &y_term);
    if (y_bytes == NULL) return make_error(env, ckzg_atoms.out_of_memory);

    ERL_NIF_TERM proof_term;
    unsigned char *proof_bytes = enif_make_new_binary(env, sizeof(KZGProof), &proof_term);
    if (proof_bytes == NULL) return make_error(env, ckzg_atoms.out_of_memory);

    C_KZG_RET ret = compute_kzg_proof(
        (KZGProof *)proof_bytes,
        (Bytes32 *)y_bytes,
        (const Blob *)blob.data,
        (const Bytes32 *)z.data,
        settings
    );
    if (ret != C_KZG_OK) return make_kzg_error(env, ret);

    return enif_make_tuple3(env, ckzg_atoms.ok, proof_term, y_term);
}

static ERL_NIF_TERM compute_blob_kzg_proof_nif(
    ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]
) {
    if (argc != 3) return make_error(env, ckzg_atoms.incorrect_arg_count);

    ErlNifBinary blob;
    if (!enif_inspect_binary(env, argv[0], &blob))
        return make_error(env, ckzg_atoms.blob_not_binary);

    if (blob.size != BYTES_PER_BLOB) return make_error(env, ckzg_atoms.invalid_blob_length);

    ErlNifBinary commitment;
    if (!enif_inspect_binary(env, argv[1], &commitment))
        return make_error(env, ckzg_atoms.commitment_not_binary);

    if (commitment.size != BYTES_PER_COMMITMENT)
        return make_error(env, ckzg_atoms.invalid_commitment_length);

    KZGSettings *settings;
    if (!enif_get_resource(env, argv[2], KZGSETTINGS_RES_TYPE, (void **)&settings))
        return make_error(env, ckzg_atoms.failed_get_settings_resource);

    ERL_NIF_TERM proof_term;
    unsigned char *proof = enif_make_new_binary(env, BYTES_PER_PROOF, &proof_term);
    if (proof == NULL) return make_error(env, ckzg_atoms.out_of_memory);

    C_KZG_RET ret = compute_blob_kzg_proof(
        (KZGProof *)proof, (const Blob *)blob.data, (const Bytes48 *)commitment.data, settings
    );
    if (ret != C_KZG_OK) return make_kzg_error(env, ret);

    return make_success(env, proof_term);
}

static ERL_NIF_TERM verify_kzg_proof_nif(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    if (argc != 5) return make_error(env, ckzg_atoms.incorrect_arg_count);

    ErlNifBinary commitment;
    if (!enif_inspect_binary(env, argv[0], &commitment))
        return make_error(env, ckzg_atoms.commitment_not_binary);

    if (commitment.size != BYTES_PER_COMMITMENT)
        return make_error(env, ckzg_atoms.invalid_commitment_length);

    ErlNifBinary z;
    if (!enif_inspect_binary(env, argv[1], &z)) return make_error(env, ckzg_atoms.z_not_binary);

    if (z.size != BYTES_PER_FIELD_ELEMENT) return make_error(env, ckzg_atoms.invalid_z_length);

    ErlNifBinary y;
    if (!enif_inspect_binary(env, argv[2], &y)) return make_error(env, ckzg_atoms.y_not_binary);

    if (y.size != BYTES_PER_FIELD_ELEMENT) return make_error(env, ckzg_atoms.invalid_y_length);

    ErlNifBinary proof;
    if (!enif_inspect_binary(env, argv[3], &proof))
        return make_error(env, ckzg_atoms.proof_not_binary);

    if (proof.size != BYTES_PER_PROOF) return make_error(env, ckzg_atoms.invalid_proof_length);

    KZGSettings *settings;
    if (!enif_get_resource(env, argv[4], KZGSETTINGS_RES_TYPE, (void **)&settings))
        return make_error(env, ckzg_atoms.failed_get_settings_resource);

    bool ok;
    C_KZG_RET ret = verify_kzg_proof(
        &ok,
        (const KZGCommitment *)commitment.data,
        (const Bytes32 *)z.data,
        (const Bytes32 *)y.data,
        (const KZGProof *)proof.data,
        settings
    );
    if (ret != C_KZG_OK) return make_kzg_error(env, ret);

    return make_success(env, ok ? ckzg_atoms.a_true : ckzg_atoms.a_false);
}

static ERL_NIF_TERM verify_blob_kzg_proof_nif(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    if (argc != 4) return make_error(env, ckzg_atoms.incorrect_arg_count);

    ErlNifBinary blob;
    if (!enif_inspect_binary(env, argv[0], &blob))
        return make_error(env, ckzg_atoms.blob_not_binary);

    if (blob.size != BYTES_PER_BLOB) return make_error(env, ckzg_atoms.invalid_blob_length);

    ErlNifBinary commitment;
    if (!enif_inspect_binary(env, argv[1], &commitment))
        return make_error(env, ckzg_atoms.commitment_not_binary);

    if (commitment.size != BYTES_PER_COMMITMENT)
        return make_error(env, ckzg_atoms.invalid_commitment_length);

    ErlNifBinary proof;
    if (!enif_inspect_binary(env, argv[2], &proof))
        return make_error(env, ckzg_atoms.proof_not_binary);

    if (proof.size != BYTES_PER_PROOF) return make_error(env, ckzg_atoms.invalid_proof_length);

    KZGSettings *settings;
    if (!enif_get_resource(env, argv[3], KZGSETTINGS_RES_TYPE, (void **)&settings))
        return make_error(env, ckzg_atoms.failed_get_settings_resource);

    bool ok;
    C_KZG_RET ret = verify_blob_kzg_proof(
        &ok,
        (const Blob *)blob.data,
        (const Bytes48 *)commitment.data,
        (const Bytes48 *)proof.data,
        settings
    );
    if (ret != C_KZG_OK) return make_kzg_error(env, ret);

    return make_success(env, ok ? ckzg_atoms.a_true : ckzg_atoms.a_false);
}

static ERL_NIF_TERM verify_blob_kzg_proof_batch_nif(
    ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]
) {
    if (argc != 4) return make_error(env, ckzg_atoms.incorrect_arg_count);

    ErlNifBinary blobs;
    if (!enif_inspect_binary(env, argv[0], &blobs))
        return make_error(env, ckzg_atoms.blob_not_binary);

    if (blobs.size % BYTES_PER_BLOB != 0) return make_error(env, ckzg_atoms.invalid_blob_length);

    ErlNifBinary commitments;
    if (!enif_inspect_binary(env, argv[1], &commitments))
        return make_error(env, ckzg_atoms.commitment_not_binary);

    if (commitments.size % BYTES_PER_COMMITMENT != 0)
        return make_error(env, ckzg_atoms.invalid_commitment_length);

    ErlNifBinary proofs;
    if (!enif_inspect_binary(env, argv[2], &proofs))
        return make_error(env, ckzg_atoms.proof_not_binary);

    if (proofs.size % BYTES_PER_PROOF != 0) return make_error(env, ckzg_atoms.invalid_proof_length);

    int blobs_len = blobs.size / BYTES_PER_BLOB;
    int commitments_len = commitments.size / BYTES_PER_COMMITMENT;
    int proofs_len = proofs.size / BYTES_PER_PROOF;
    if (commitments_len != blobs_len || commitments_len != proofs_len)
        return make_error(env, ckzg_atoms.expected_same_array_size);

    KZGSettings *settings;
    if (!enif_get_resource(env, argv[3], KZGSETTINGS_RES_TYPE, (void **)&settings))
        return make_error(env, ckzg_atoms.failed_get_settings_resource);

    bool ok;
    C_KZG_RET ret = verify_blob_kzg_proof_batch(
        &ok,
        (const Blob *)blobs.data,
        (const Bytes48 *)commitments.data,
        (const Bytes48 *)proofs.data,
        blobs_len,
        settings
    );
    if (ret != C_KZG_OK) return make_kzg_error(env, ret);

    return make_success(env, ok ? ckzg_atoms.a_true : ckzg_atoms.a_false);
}

static ERL_NIF_TERM compute_cells_nif(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    ERL_NIF_TERM *cells_list = NULL;
    Cell *cells = NULL;
    ERL_NIF_TERM msg;

    if (argc != 2) {
        msg = make_error(env, ckzg_atoms.incorrect_arg_count);
        goto out;
    }

    ErlNifBinary blob;
    if (!enif_inspect_binary(env, argv[0], &blob)) {
        msg = make_error(env, ckzg_atoms.blob_not_binary);
        goto out;
    }

    if (blob.size != BYTES_PER_BLOB) {
        msg = make_error(env, ckzg_atoms.invalid_blob_length);
        goto out;
    }

    KZGSettings *settings;
    if (!enif_get_resource(env, argv[1], KZGSETTINGS_RES_TYPE, (void **)&settings)) {
        msg = make_error(env, ckzg_atoms.failed_get_settings_resource);
        goto out;
    }

    cells = enif_alloc(BYTES_PER_CELL * CELLS_PER_EXT_BLOB);
    if (cells == NULL) {
        msg = make_error(env, ckzg_atoms.out_of_memory);
        goto out;
    }

    C_KZG_RET ret = compute_cells_and_kzg_proofs(cells, NULL, (const Blob *)blob.data, settings);
    if (ret != C_KZG_OK) {
        msg = make_kzg_error(env, ret);
        goto out;
    }

    cells_list = enif_alloc(sizeof(ERL_NIF_TERM) * CELLS_PER_EXT_BLOB);
    if (cells_list == NULL) {
        msg = make_error(env, ckzg_atoms.out_of_memory);
        goto out;
    }

    for (int i = 0; i < CELLS_PER_EXT_BLOB; i++) {
        ERL_NIF_TERM cell_term;
        unsigned char *cell_bytes = enif_make_new_binary(env, BYTES_PER_CELL, &cell_term);
        if (cell_bytes == NULL) {
            msg = make_error(env, ckzg_atoms.out_of_memory);
            goto out;
        }

        memcpy(cell_bytes, &cells[i], BYTES_PER_CELL);
        cells_list[i] = cell_term;
    }

    ERL_NIF_TERM cells_term = enif_make_list_from_array(env, cells_list, CELLS_PER_EXT_BLOB);
    msg = make_success(env, cells_term);

out:
    enif_free(cells);
    enif_free(cells_list);
    return msg;
}

static ERL_NIF_TERM compute_cells_and_kzg_proofs_nif(
    ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]
) {
    ERL_NIF_TERM *cells_list = NULL, *proofs_list = NULL;
    KZGProof *proofs = NULL;
    Cell *cells = NULL;
    ERL_NIF_TERM msg;

    if (argc != 2) return make_error(env, ckzg_atoms.incorrect_arg_count);

    ErlNifBinary blob;
    if (!enif_inspect_binary(env, argv[0], &blob)) {
        msg = make_error(env, ckzg_atoms.blob_not_binary);
        goto out;
    }

    if (blob.size != BYTES_PER_BLOB) {
        msg = make_error(env, ckzg_atoms.invalid_blob_length);
        goto out;
    }

    KZGSettings *settings;
    if (!enif_get_resource(env, argv[1], KZGSETTINGS_RES_TYPE, (void **)&settings)) {
        msg = make_error(env, ckzg_atoms.failed_get_settings_resource);
        goto out;
    }

    cells_list = enif_alloc(sizeof(ERL_NIF_TERM) * CELLS_PER_EXT_BLOB);
    if (cells_list == NULL) {
        msg = make_error(env, ckzg_atoms.out_of_memory);
        goto out;
    }

    proofs_list = enif_alloc(sizeof(ERL_NIF_TERM) * CELLS_PER_EXT_BLOB);
    if (proofs_list == NULL) {
        msg = make_error(env, ckzg_atoms.out_of_memory);
        goto out;
    }

    cells = enif_alloc(BYTES_PER_CELL * CELLS_PER_EXT_BLOB);
    if (cells == NULL) {
        msg = make_error(env, ckzg_atoms.out_of_memory);
        goto out;
    }

    proofs = enif_alloc(BYTES_PER_PROOF * CELLS_PER_EXT_BLOB);
    if (proofs == NULL) {
        msg = make_error(env, ckzg_atoms.out_of_memory);
        goto out;
    }

    C_KZG_RET ret = compute_cells_and_kzg_proofs(cells, proofs, (const Blob *)blob.data, settings);
    if (ret != C_KZG_OK) {
        msg = make_kzg_error(env, ret);
        goto out;
    }

    for (int i = 0; i < CELLS_PER_EXT_BLOB; i++) {
        ERL_NIF_TERM cell_term;
        unsigned char *cell_bytes = enif_make_new_binary(env, BYTES_PER_CELL, &cell_term);
        if (cell_bytes == NULL) {
            msg = make_error(env, ckzg_atoms.out_of_memory);
            goto out;
        }

        memcpy(cell_bytes, &cells[i], BYTES_PER_CELL);
        cells_list[i] = cell_term;

        ERL_NIF_TERM proof_term;
        unsigned char *proof_bytes = enif_make_new_binary(env, BYTES_PER_PROOF, &proof_term);
        if (proof_bytes == NULL) {
            msg = make_error(env, ckzg_atoms.out_of_memory);
            goto out;
        }

        memcpy(proof_bytes, &proofs[i], BYTES_PER_PROOF);
        proofs_list[i] = proof_term;
    }

    ERL_NIF_TERM cells_term = enif_make_list_from_array(env, cells_list, CELLS_PER_EXT_BLOB);
    ERL_NIF_TERM proofs_term = enif_make_list_from_array(env, proofs_list, CELLS_PER_EXT_BLOB);
    msg = enif_make_tuple3(env, ckzg_atoms.ok, cells_term, proofs_term);

out:
    enif_free(cells_list);
    enif_free(proofs_list);
    enif_free(cells);
    enif_free(proofs);
    return msg;
}

static ERL_NIF_TERM recover_cells_and_kzg_proofs_nif(
    ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]
) {
    ERL_NIF_TERM *cells_list = NULL, *proofs_list = NULL;
    Cell *cells = NULL, *recovered_cells = NULL;
    KZGProof *recovered_proofs = NULL;
    uint64_t *cell_indices = NULL;
    ERL_NIF_TERM msg;

    if (argc != 3) {
        msg = make_error(env, ckzg_atoms.incorrect_arg_count);
        goto out;
    }

    unsigned int cell_indices_len;
    if (!enif_get_list_length(env, argv[0], &cell_indices_len)) {
        msg = make_error(env, ckzg_atoms.cell_indices_not_list);
        goto out;
    }

    unsigned int cells_len;
    if (!enif_get_list_length(env, argv[1], &cells_len)) {
        msg = make_error(env, ckzg_atoms.cells_not_list);
        goto out;
    }

    if (cells_len != cell_indices_len) {
        msg = make_error(env, ckzg_atoms.expected_same_array_size);
        goto out;
    }

    KZGSettings *settings;
    if (!enif_get_resource(env, argv[2], KZGSETTINGS_RES_TYPE, (void **)&settings)) {
        msg = make_error(env, ckzg_atoms.failed_get_settings_resource);
        goto out;
    }

    cell_indices = enif_alloc(cell_indices_len * sizeof(uint64_t));
    if (cell_indices == NULL) {
        msg = make_error(env, ckzg_atoms.out_of_memory);
        goto out;
    }

    ERL_NIF_TERM head;
    ERL_NIF_TERM tail = argv[0];

    for (int i = 0; enif_get_list_cell(env, tail, &head, &tail); i++) {
        ErlNifUInt64 current_u;
        if (!enif_get_uint64(env, head, &current_u)) {
            msg = make_error(env, ckzg_atoms.cell_indices_value_not_uint64);
            goto out;
        }

        cell_indices[i] = (uint64_t)current_u;
    }

    cells = enif_alloc(cells_len * BYTES_PER_CELL);
    if (cells == NULL) {
        msg = make_error(env, ckzg_atoms.out_of_memory);
        goto out;
    }

    tail = argv[1];
    for (int i = 0; enif_get_list_cell(env, tail, &head, &tail); i++) {
        ErlNifBinary current_b;
        if (!enif_inspect_binary(env, head, &current_b)) {
            msg = make_error(env, ckzg_atoms.cells_value_not_binary);
            goto out;
        }

        if (current_b.size != BYTES_PER_CELL) {
            msg = make_error(env, ckzg_atoms.invalid_cell_length);
            goto out;
        }

        memcpy(&cells[i], current_b.data, BYTES_PER_CELL);
    }

    recovered_cells = enif_alloc(CELLS_PER_EXT_BLOB * BYTES_PER_CELL);
    if (recovered_cells == NULL) {
        msg = make_error(env, ckzg_atoms.out_of_memory);
        goto out;
    }

    recovered_proofs = enif_alloc(CELLS_PER_EXT_BLOB * BYTES_PER_PROOF);
    if (recovered_proofs == NULL) {
        msg = make_error(env, ckzg_atoms.out_of_memory);
        goto out;
    }

    C_KZG_RET ret = recover_cells_and_kzg_proofs(
        recovered_cells, recovered_proofs, cell_indices, cells, cells_len, settings
    );
    if (ret != C_KZG_OK) {
        msg = make_kzg_error(env, ret);
        goto out;
    }

    cells_list = enif_alloc(sizeof(ERL_NIF_TERM) * CELLS_PER_EXT_BLOB);
    if (cells_list == NULL) {
        msg = make_error(env, ckzg_atoms.out_of_memory);
        goto out;
    }

    proofs_list = enif_alloc(sizeof(ERL_NIF_TERM) * CELLS_PER_EXT_BLOB);
    if (proofs_list == NULL) {
        msg = make_error(env, ckzg_atoms.out_of_memory);
        goto out;
    }

    for (int i = 0; i < CELLS_PER_EXT_BLOB; i++) {
        ErlNifBinary cell_bytes;
        if (!enif_alloc_binary(BYTES_PER_CELL, &cell_bytes)) {
            msg = make_error(env, ckzg_atoms.out_of_memory);
            goto out;
        }

        memcpy(cell_bytes.data, &recovered_cells[i], BYTES_PER_CELL);
        cells_list[i] = enif_make_binary(env, &cell_bytes);

        ErlNifBinary proof_bytes;
        if (!enif_alloc_binary(BYTES_PER_PROOF, &proof_bytes)) {
            msg = make_error(env, ckzg_atoms.out_of_memory);
            goto out;
        }

        memcpy(proof_bytes.data, &recovered_proofs[i], BYTES_PER_PROOF);
        proofs_list[i] = enif_make_binary(env, &proof_bytes);
    }

    ERL_NIF_TERM cells_term = enif_make_list_from_array(env, cells_list, CELLS_PER_EXT_BLOB);
    ERL_NIF_TERM proofs_term = enif_make_list_from_array(env, proofs_list, CELLS_PER_EXT_BLOB);
    msg = enif_make_tuple3(env, ckzg_atoms.ok, cells_term, proofs_term);

out:
    enif_free(cell_indices);
    enif_free(cells);
    enif_free(recovered_cells);
    enif_free(recovered_proofs);
    enif_free(cells_list);
    enif_free(proofs_list);
    return msg;
}

static ERL_NIF_TERM verify_cell_kzg_proof_batch_nif(
    ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]
) {
    Bytes48 *commitments = NULL, *proofs = NULL;
    uint64_t *cell_indices = NULL;
    Cell *cells = NULL;
    ERL_NIF_TERM msg;

    if (argc != 5) {
        msg = make_error(env, ckzg_atoms.incorrect_arg_count);
        goto out;
    }

    unsigned int commitments_len;
    if (!enif_get_list_length(env, argv[0], &commitments_len)) {
        msg = make_error(env, ckzg_atoms.commitments_not_list);
        goto out;
    }

    unsigned int cell_indices_len;
    if (!enif_get_list_length(env, argv[1], &cell_indices_len)) {
        msg = make_error(env, ckzg_atoms.cell_indices_not_list);
        goto out;
    }

    unsigned int cells_len;
    if (!enif_get_list_length(env, argv[2], &cells_len)) {
        msg = make_error(env, ckzg_atoms.cells_not_list);
        goto out;
    }

    unsigned int proofs_len;
    if (!enif_get_list_length(env, argv[3], &proofs_len)) {
        msg = make_error(env, ckzg_atoms.proofs_not_list);
        goto out;
    }

    if (proofs_len != cells_len || cells_len != cell_indices_len ||
        cell_indices_len != commitments_len) {
        msg = make_error(env, ckzg_atoms.expected_same_array_size);
        goto out;
    }

    KZGSettings *settings;
    if (!enif_get_resource(env, argv[4], KZGSETTINGS_RES_TYPE, (void **)&settings)) {
        msg = make_error(env, ckzg_atoms.failed_get_settings_resource);
        goto out;
    }

    commitments = enif_alloc(commitments_len * BYTES_PER_COMMITMENT);
    if (commitments == NULL) {
        msg = make_error(env, ckzg_atoms.out_of_memory);
        goto out;
    }

    ERL_NIF_TERM head;
    ERL_NIF_TERM tail = argv[0];

    for (int i = 0; enif_get_list_cell(env, tail, &head, &tail); i++) {
        ErlNifBinary current_b;
        if (!enif_inspect_binary(env, head, &current_b)) {
            msg = make_error(env, ckzg_atoms.commitment_not_binary);
            goto out;
        }

        if (current_b.size != BYTES_PER_COMMITMENT) {
            msg = make_error(env, ckzg_atoms.commitment_not_binary);
            goto out;
        }

        memcpy(&commitments[i], current_b.data, BYTES_PER_COMMITMENT);
    }

    cell_indices = enif_alloc(cell_indices_len * sizeof(uint64_t));
    if (cell_indices == NULL) {
        msg = make_error(env, ckzg_atoms.out_of_memory);
        goto out;
    }

    tail = argv[1];
    for (int i = 0; enif_get_list_cell(env, tail, &head, &tail); i++) {
        ErlNifUInt64 current_u;
        if (!enif_get_uint64(env, head, &current_u)) {
            msg = make_error(env, ckzg_atoms.cell_indices_value_not_uint64);
            goto out;
        }

        cell_indices[i] = (uint64_t)current_u;
    }

    cells = enif_alloc(cells_len * BYTES_PER_CELL);
    if (cells == NULL) {
        msg = make_error(env, ckzg_atoms.out_of_memory);
        goto out;
    }

    tail = argv[2];
    for (int i = 0; enif_get_list_cell(env, tail, &head, &tail); i++) {
        ErlNifBinary current_b;
        if (!enif_inspect_binary(env, head, &current_b)) {
            msg = make_error(env, ckzg_atoms.cells_value_not_binary);
            goto out;
        }

        if (current_b.size != BYTES_PER_CELL) {
            msg = make_error(env, ckzg_atoms.invalid_cell_length);
            goto out;
        }

        memcpy(&cells[i], current_b.data, BYTES_PER_CELL);
    }

    proofs = enif_alloc(proofs_len * BYTES_PER_PROOF);
    if (proofs == NULL) {
        msg = make_error(env, ckzg_atoms.out_of_memory);
        goto out;
    }

    tail = argv[3];
    for (int i = 0; enif_get_list_cell(env, tail, &head, &tail); i++) {
        ErlNifBinary current_b;
        if (!enif_inspect_binary(env, head, &current_b)) {
            msg = make_error(env, ckzg_atoms.proof_not_binary);
            goto out;
        }

        if (current_b.size != BYTES_PER_PROOF) {
            msg = make_error(env, ckzg_atoms.invalid_proof_length);
            goto out;
        }

        memcpy(&proofs[i], current_b.data, BYTES_PER_PROOF);
    }

    bool ok;
    C_KZG_RET ret = verify_cell_kzg_proof_batch(
        &ok, commitments, cell_indices, cells, proofs, cells_len, settings
    );

    if (ret != C_KZG_OK) {
        msg = make_kzg_error(env, ret);
        goto out;
    }

    msg = make_success(env, ok ? ckzg_atoms.a_true : ckzg_atoms.a_false);

out:
    enif_free(commitments);
    enif_free(cell_indices);
    enif_free(cells);
    enif_free(proofs);
    return msg;
}

static ErlNifFunc nif_funcs[] = {
    {"load_trusted_setup", 2, load_trusted_setup_nif, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"blob_to_kzg_commitment", 2, blob_to_kzg_commitment_nif, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"compute_kzg_proof", 3, compute_kzg_proof_nif, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"compute_blob_kzg_proof", 3, compute_blob_kzg_proof_nif, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"verify_kzg_proof", 5, verify_kzg_proof_nif, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"verify_blob_kzg_proof", 4, verify_blob_kzg_proof_nif, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"verify_blob_kzg_proof_batch", 4, verify_blob_kzg_proof_batch_nif, ERL_NIF_DIRTY_JOB_CPU_BOUND
    },
    {"compute_cells", 2, compute_cells_nif, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"compute_cells_and_kzg_proofs",
     2,
     compute_cells_and_kzg_proofs_nif,
     ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"recover_cells_and_kzg_proofs",
     3,
     recover_cells_and_kzg_proofs_nif,
     ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"verify_cell_kzg_proof_batch", 5, verify_cell_kzg_proof_batch_nif, ERL_NIF_DIRTY_JOB_CPU_BOUND}
};
ERL_NIF_INIT(Elixir.KZG, nif_funcs, load, NULL, NULL, NULL);
