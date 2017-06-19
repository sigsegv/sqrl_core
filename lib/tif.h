#ifndef SQRL_TIF_H
#define SQRL_TIF_H

enum sqrl_tif_flag {
    e_tif_id_match                  = 0x0001,
    e_tif_prev_id_match             = 0x0002,
    e_tif_ip_match                  = 0x0004,
    e_tif_sqrl_disabled             = 0x0008,
    e_tif_func_not_supported        = 0x0010,
    e_tif_transient_error           = 0x0020,
    e_tif_command_failed            = 0x0040,
    e_tif_client_failure            = 0x0080,
    e_tif_bad_id_association        = 0x0100,
    e_tif_invalid_link_origin       = 0x0200,
    e_tif_suppress_sfn_confirmation = 0x0400
};

#endif