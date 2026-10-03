/*
*** pathcipher.c
*** by Iain Donald
*** mod 20261002, created 20261002.

A Tcl/Tk demo of the my library ascon-lib. ascon-lib is an implementation of the NIST SP 800-232 standard: 

"Ascon-Based Lightweight Cryptography Standards for Constrained Devices: Authenticated Encryption, Hash, and Extendable Output Functions" 

The Tk script is embedded below and run by the embedded Tcl interpreter. The Ascon calls are registered as Tcl commands.

// how to build
Debian: apt install tcl-dev tk-dev.
zig cc -std=c99 -O2 -I/usr/include/tcl8.6 pathcipher.c libascon.a -ltcl8.6 -ltk8.6 -o pathcipher
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tcl.h>
#include <tk.h>
#include "include/ascon.h"
// Tcl 9 uses Tcl_Size for argument counts, Tcl 8.6 uses int.
#ifndef TCL_SIZE_MAX
typedef int Tcl_Size;
#endif
#define MAX_OUT 4096

// One live incremental context per mode, each created by its init command.
static ascon_hash256_ctx hash_ctx;
static int hash_ready = 0;
static ascon_xof128_ctx xof_ctx;
static int xof_ready = 0;
static ascon_cxof128_ctx cxof_ctx;
static int cxof_ready = 0;

// Number of update calls since the last init.
static int hash_updates = 0;
static int xof_updates = 0;
static int cxof_updates = 0;

// helpers //
static int hex_val(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

// Decode a hex string into out. Returns the byte count, or -1 if malformed or longer than out_max.
static long hex_decode(const char *hex, uint8_t *out, size_t out_max) {
  size_t len = strlen(hex);
  size_t i;
  if (len % 2 != 0 || len / 2 > out_max) return -1;
  for (i = 0; i < len; i += 2) {
    int high = hex_val(hex[i]);
    int low = hex_val(hex[i + 1]);
    if (high < 0 || low < 0) return -1;
    out[i / 2] = (uint8_t)((high << 4) | low);
  }
  return (long)(len / 2);
}

static void set_hex_result(Tcl_Interp *interp, const uint8_t *data, size_t len) {
  char *hex = malloc(len * 2 + 1);
  size_t i;
  if (hex == NULL) return;
  for (i = 0; i < len; i++) sprintf(hex + i * 2, "%02x", data[i]);
  Tcl_SetObjResult(interp, Tcl_NewStringObj(hex, -1));
  free(hex);
}

static int fail(Tcl_Interp *interp, const char *msg) {
  Tcl_SetObjResult(interp, Tcl_NewStringObj(msg, -1));
  return TCL_ERROR;
}

static int check_args(Tcl_Interp *interp, Tcl_Size objc, Tcl_Obj *const objv[], int count, const char *usage) {
  if (objc != count + 1) {
    Tcl_WrongNumArgs(interp, 1, objv, usage);
    return 0;
  }
  return 1;
}

static int get_length(Tcl_Interp *interp, Tcl_Obj *obj, int *len) {
  if (Tcl_GetIntFromObj(interp, obj, len) != TCL_OK) return TCL_ERROR;
  if (*len < 1 || *len > MAX_OUT) return fail(interp, "length must be 1..4096");
  return TCL_OK;
}

static int get_count(Tcl_Interp *interp, Tcl_Obj *obj, int *n) {
  if (Tcl_GetIntFromObj(interp, obj, n) != TCL_OK) return TCL_ERROR;
  if (*n < 1 || *n > MAX_OUT) return fail(interp, "updates must be 1..4096");
  return TCL_OK;
}


// Show a result as "output: <hex>".
static void set_output(Tcl_Interp *interp, const uint8_t *data, size_t len) {
  char *hex = malloc(len * 2 + 1);
  size_t i;
  if (hex == NULL) return;
  for (i = 0; i < len; i++) sprintf(hex + i * 2, "%02x", data[i]);
  hex[len * 2] = '\0';
  Tcl_SetObjResult(interp, Tcl_ObjPrintf("output: %s", hex));
  free(hex);
}

// Hash256 //
static int cmd_hash_oneshot(ClientData cd, Tcl_Interp *interp, Tcl_Size objc, Tcl_Obj *const objv[]) {
  const char *msg;
  size_t msg_len;
  int n, k;
  uint8_t digest[ASCON_HASH256_SIZE];
  ascon_hash256_ctx ctx;
  (void)cd;
  if (!check_args(interp, objc, objv, 2, "text updates")) return TCL_ERROR;
  if (get_count(interp, objv[2], &n) != TCL_OK) return TCL_ERROR;
  msg = Tcl_GetString(objv[1]);
  msg_len = strlen(msg);

  ascon_hash256_init(&ctx);
  for (k = 0; k < n; k++) ascon_hash256_update(&ctx, (const uint8_t *)msg, msg_len);
  ascon_hash256_final(&ctx, digest);

  set_output(interp, digest, sizeof digest);
  return TCL_OK;
}

static int cmd_hash_init(ClientData cd, Tcl_Interp *interp, Tcl_Size objc, Tcl_Obj *const objv[]) {
  (void)cd;
  if (!check_args(interp, objc, objv, 0, "")) return TCL_ERROR;
  ascon_hash256_init(&hash_ctx);
  hash_ready = 1;
  hash_updates = 0;
  Tcl_SetObjResult(interp, Tcl_NewStringObj("initialized", -1));
  return TCL_OK;
}

static int cmd_hash_update(ClientData cd, Tcl_Interp *interp, Tcl_Size objc, Tcl_Obj *const objv[]) {
  const char *msg;
  (void)cd;
  if (!check_args(interp, objc, objv, 1, "text")) return TCL_ERROR;
  if (!hash_ready) return fail(interp, "run Init first");
  msg = Tcl_GetString(objv[1]);
  ascon_hash256_update(&hash_ctx, (const uint8_t *)msg, strlen(msg));
  hash_updates++;
  Tcl_SetObjResult(interp, Tcl_ObjPrintf("absorbed, update #%d", hash_updates));
  return TCL_OK;
}

static int cmd_hash_final(ClientData cd, Tcl_Interp *interp, Tcl_Size objc, Tcl_Obj *const objv[]) {
  uint8_t digest[ASCON_HASH256_SIZE];
  (void)cd;
  if (!check_args(interp, objc, objv, 0, "")) return TCL_ERROR;
  if (!hash_ready) return fail(interp, "run Init first");
  ascon_hash256_final(&hash_ctx, digest);
  hash_ready = 0;
  set_hex_result(interp, digest, sizeof digest);
  return TCL_OK;
}

// XOF128 //
static int cmd_xof_oneshot(ClientData cd, Tcl_Interp *interp, Tcl_Size objc, Tcl_Obj *const objv[]) {
  const char *msg;
  size_t msg_len;
  int len, n, k;
  uint8_t *out;
  ascon_xof128_ctx ctx;
  (void)cd;
  if (!check_args(interp, objc, objv, 3, "text length updates")) return TCL_ERROR;
  if (get_length(interp, objv[2], &len) != TCL_OK) return TCL_ERROR;
  if (get_count(interp, objv[3], &n) != TCL_OK) return TCL_ERROR;
  msg = Tcl_GetString(objv[1]);
  msg_len = strlen(msg);
  out = malloc((size_t)len);
  if (out == NULL) return fail(interp, "out of memory");

  ascon_xof128_init(&ctx);
  for (k = 0; k < n; k++) ascon_xof128_update(&ctx, (const uint8_t *)msg, msg_len);
  ascon_xof128_squeeze(&ctx, out, (size_t)len);

  set_output(interp, out, (size_t)len);
  free(out);
  return TCL_OK;
}

static int cmd_xof_init(ClientData cd, Tcl_Interp *interp, Tcl_Size objc, Tcl_Obj *const objv[]) {
  (void)cd;
  if (!check_args(interp, objc, objv, 0, "")) return TCL_ERROR;
  ascon_xof128_init(&xof_ctx);
  xof_ready = 1;
  xof_updates = 0;
  Tcl_SetObjResult(interp, Tcl_NewStringObj("initialized", -1));
  return TCL_OK;
}

static int cmd_xof_update(ClientData cd, Tcl_Interp *interp, Tcl_Size objc, Tcl_Obj *const objv[]) {
  const char *msg;
  (void)cd;
  if (!check_args(interp, objc, objv, 1, "text")) return TCL_ERROR;
  if (!xof_ready) return fail(interp, "run Init first");
  if (xof_ctx.squeezing) return fail(interp, "cannot absorb after squeezing has begun");
  msg = Tcl_GetString(objv[1]);
  ascon_xof128_update(&xof_ctx, (const uint8_t *)msg, strlen(msg));
  xof_updates++;
  Tcl_SetObjResult(interp, Tcl_ObjPrintf("absorbed, update #%d", xof_updates));
  return TCL_OK;
}

static int cmd_xof_squeeze(ClientData cd, Tcl_Interp *interp, Tcl_Size objc, Tcl_Obj *const objv[]) {
  int len;
  uint8_t *out;
  (void)cd;
  if (!check_args(interp, objc, objv, 1, "length")) return TCL_ERROR;
  if (!xof_ready) return fail(interp, "run Init first");
  if (get_length(interp, objv[1], &len) != TCL_OK) return TCL_ERROR;
  out = malloc((size_t)len);
  if (out == NULL) return fail(interp, "out of memory");
  ascon_xof128_squeeze(&xof_ctx, out, (size_t)len);
  set_hex_result(interp, out, (size_t)len);
  free(out);
  return TCL_OK;
}

// CXOF128 //
static int cmd_cxof_oneshot(ClientData cd, Tcl_Interp *interp, Tcl_Size objc, Tcl_Obj *const objv[]) {
  const char *msg;
  const char *cs;
  size_t msg_len;
  int len, n, k;
  uint8_t *out;
  ascon_cxof128_ctx ctx;
  (void)cd;
  if (!check_args(interp, objc, objv, 4, "text customization length updates")) return TCL_ERROR;
  if (get_length(interp, objv[3], &len) != TCL_OK) return TCL_ERROR;
  if (get_count(interp, objv[4], &n) != TCL_OK) return TCL_ERROR;
  msg = Tcl_GetString(objv[1]);
  cs = Tcl_GetString(objv[2]);
  msg_len = strlen(msg);

  if (ascon_cxof128_init(&ctx, (const uint8_t *)cs, strlen(cs)) != ASCON_OK) return fail(interp, "customization string too long (max 256 bytes)");

  out = malloc((size_t)len);
  if (out == NULL) return fail(interp, "out of memory");
  for (k = 0; k < n; k++) ascon_cxof128_update(&ctx, (const uint8_t *)msg, msg_len);
  ascon_cxof128_squeeze(&ctx, out, (size_t)len);

  set_output(interp, out, (size_t)len);
  free(out);
  return TCL_OK;
}

static int cmd_cxof_init(ClientData cd, Tcl_Interp *interp, Tcl_Size objc, Tcl_Obj *const objv[]) {
  const char *cs;
  (void)cd;
  if (!check_args(interp, objc, objv, 1, "customization")) return TCL_ERROR;
  cs = Tcl_GetString(objv[1]);
  if (ascon_cxof128_init(&cxof_ctx, (const uint8_t *)cs, strlen(cs)) != ASCON_OK) {
    cxof_ready = 0;
    return fail(interp, "customization string too long (max 256 bytes)");
  }
  cxof_ready = 1;
  cxof_updates = 0;
  Tcl_SetObjResult(interp, Tcl_NewStringObj("initialized", -1));
  return TCL_OK;
}

static int cmd_cxof_update(ClientData cd, Tcl_Interp *interp, Tcl_Size objc, Tcl_Obj *const objv[]) {
  const char *msg;
  (void)cd;
  if (!check_args(interp, objc, objv, 1, "text")) return TCL_ERROR;
  if (!cxof_ready) return fail(interp, "run Init first");
  if (cxof_ctx.squeezing) return fail(interp, "cannot absorb after squeezing has begun");
  msg = Tcl_GetString(objv[1]);
  ascon_cxof128_update(&cxof_ctx, (const uint8_t *)msg, strlen(msg));
  cxof_updates++;
  Tcl_SetObjResult(interp, Tcl_ObjPrintf("absorbed, update #%d", cxof_updates));
  return TCL_OK;
}

static int cmd_cxof_squeeze(ClientData cd, Tcl_Interp *interp, Tcl_Size objc, Tcl_Obj *const objv[]) {
  int len;
  uint8_t *out;
  (void)cd;
  if (!check_args(interp, objc, objv, 1, "length")) return TCL_ERROR;
  if (!cxof_ready) return fail(interp, "run Init first");
  if (get_length(interp, objv[1], &len) != TCL_OK) return TCL_ERROR;
  out = malloc((size_t)len);
  if (out == NULL) return fail(interp, "out of memory");
  ascon_cxof128_squeeze(&cxof_ctx, out, (size_t)len);
  set_hex_result(interp, out, (size_t)len);
  free(out);
  return TCL_OK;
}

// AEAD128 //
// Returns a two element list: {ciphertext_hex tag_hex}.
static int cmd_aead_encrypt(ClientData cd, Tcl_Interp *interp, Tcl_Size objc, Tcl_Obj *const objv[]) {
  const char *pt;
  const char *ad;
  uint8_t key[ASCON_AEAD128_KEY_SIZE];
  uint8_t nonce[ASCON_AEAD128_NONCE_SIZE];
  uint8_t tag[ASCON_AEAD128_TAG_SIZE];
  uint8_t *ct;
  size_t pt_len;
  char *ct_hex;
  char *tag_hex;
  size_t i;
  Tcl_Obj *list;
  (void)cd;
  if (!check_args(interp, objc, objv, 4, "plaintext ad key_hex nonce_hex")) return TCL_ERROR;
  if (hex_decode(Tcl_GetString(objv[3]), key, sizeof key) != ASCON_AEAD128_KEY_SIZE) return fail(interp, "key must be 32 hex characters");
  if (hex_decode(Tcl_GetString(objv[4]), nonce, sizeof nonce) != ASCON_AEAD128_NONCE_SIZE) return fail(interp, "nonce must be 32 hex characters");
  pt = Tcl_GetString(objv[1]);
  ad = Tcl_GetString(objv[2]);
  pt_len = strlen(pt);

  ct = malloc(pt_len + 1);
  ct_hex = malloc(pt_len * 2 + 1);
  tag_hex = malloc(sizeof tag * 2 + 1);
  if (ct == NULL || ct_hex == NULL || tag_hex == NULL) {
    free(ct);
    free(ct_hex);
    free(tag_hex);
    return fail(interp, "out of memory");
  }

  ascon_aead128_encrypt(ct, tag, (const uint8_t *)pt, pt_len, (const uint8_t *)ad, strlen(ad), key, nonce);

  for (i = 0; i < pt_len; i++) sprintf(ct_hex + i * 2, "%02x", ct[i]);
  ct_hex[pt_len * 2] = '\0';
  for (i = 0; i < sizeof tag; i++) sprintf(tag_hex + i * 2, "%02x", tag[i]);

  list = Tcl_NewListObj(0, NULL);
  Tcl_ListObjAppendElement(interp, list, Tcl_NewStringObj(ct_hex, -1));
  Tcl_ListObjAppendElement(interp, list, Tcl_NewStringObj(tag_hex, -1));
  Tcl_SetObjResult(interp, list);

  free(ct);
  free(ct_hex);
  free(tag_hex);
  return TCL_OK;
}

static int cmd_aead_decrypt(ClientData cd, Tcl_Interp *interp, Tcl_Size objc, Tcl_Obj *const objv[]) {
  const char *ct_hex;
  const char *ad;
  uint8_t key[ASCON_AEAD128_KEY_SIZE];
  uint8_t nonce[ASCON_AEAD128_NONCE_SIZE];
  uint8_t tag[ASCON_AEAD128_TAG_SIZE];
  uint8_t *ct;
  uint8_t *pt;
  long ct_len;
  int rc;
  (void)cd;
  if (!check_args(interp, objc, objv, 5, "ciphertext_hex tag_hex ad key_hex nonce_hex")) return TCL_ERROR;
  if (hex_decode(Tcl_GetString(objv[2]), tag, sizeof tag) != ASCON_AEAD128_TAG_SIZE) return fail(interp, "tag must be 32 hex characters");
  if (hex_decode(Tcl_GetString(objv[4]), key, sizeof key) != ASCON_AEAD128_KEY_SIZE) return fail(interp, "key must be 32 hex characters");
  if (hex_decode(Tcl_GetString(objv[5]), nonce, sizeof nonce) != ASCON_AEAD128_NONCE_SIZE) return fail(interp, "nonce must be 32 hex characters");
  ct_hex = Tcl_GetString(objv[1]);
  ad = Tcl_GetString(objv[3]);

  ct = malloc(strlen(ct_hex) / 2 + 1);
  pt = malloc(strlen(ct_hex) / 2 + 1);
  if (ct == NULL || pt == NULL) {
    free(ct);
    free(pt);
    return fail(interp, "out of memory");
  }
  ct_len = hex_decode(ct_hex, ct, strlen(ct_hex) / 2 + 1);
  if (ct_len < 0) {
    free(ct);
    free(pt);
    return fail(interp, "ciphertext is not valid hex");
  }

  rc = ascon_aead128_decrypt(pt, ct, (size_t)ct_len, tag, (const uint8_t *)ad, strlen(ad), key, nonce);
  if (rc != ASCON_OK) {
    free(ct);
    free(pt);
    return fail(interp, "authentication failed (output zeroed)");
  }
  pt[ct_len] = '\0';
  Tcl_SetObjResult(interp, Tcl_NewStringObj((const char *)pt, -1));
  free(ct);
  free(pt);
  return TCL_OK;
}

// GUI script //
static const char *gui_script =
  "package require Tk\n"
  "wm title . {Ascon demo}\n"
  // Ask the window manager to float the window (tiling WMs honor the dialog type, others ignore it).
  "catch {wm attributes . -type dialog}\n"
  "wm geometry . 640x460\n"
  "wm minsize . 480 300\n"

  // Dark grey theme on top of clam.
  "set bg #2b2b2b\n"
  "set fbg #3a3a3a\n"
  "set mid #4a4a4a\n"
  "set fg #e0e0e0\n"
  "ttk::style theme use clam\n"
  "ttk::style configure . -background $bg -foreground $fg -fieldbackground $fbg -bordercolor #444444 -lightcolor $bg -darkcolor $bg -troughcolor $bg -insertcolor $fg\n"
  "ttk::style configure TNotebook -background $bg\n"
  "ttk::style configure TNotebook.Tab -background $mid -foreground $fg -padding {10 3}\n"
  "ttk::style map TNotebook.Tab -background [list selected $fbg] -foreground [list selected #ffffff]\n"
  "ttk::style configure TButton -background $mid -foreground $fg\n"
  "ttk::style map TButton -background [list active #5a5a5a pressed #666666]\n"
  ". configure -background $bg\n"

  // Escape quits from anywhere in the window.
  "bind all <Escape> {destroy .}\n"
  "ttk::notebook .nb\n"
  // 11px margin around the notebook, shown in the root's background color.
  "pack .nb -fill both -expand 1 -padx 11 -pady 11\n"

  // Add a tab, returns its frame path.
  "proc tab {name} {\n"
  "  set w .nb.[string tolower $name]\n"
  "  ttk::frame $w\n"
  "  .nb add $w -text $name\n"
  // Inputs in row 0 and output in row 1, split 3:2 of the available height. The uniform group makes the ratio hold regardless of requested sizes.
  "  ttk::frame $w.in\n"
  "  grid $w.in -row 0 -column 0 -sticky nsew\n"
  "  grid columnconfigure $w 0 -weight 1\n"
  "  grid columnconfigure $w.in 1 -weight 1\n"
  "  grid rowconfigure $w 0 -weight 3 -uniform split\n"
  "  grid rowconfigure $w 1 -weight 2 -uniform split\n"
  "  return $w\n"
  "}\n"

  // A labelled entry on grid row r, read back as $w.e$r.
  "proc field {w r label {init {}}} {\n"
  "  ttk::label $w.in.l$r -text $label\n"
  "  ttk::entry $w.in.e$r -width 30\n"
  "  $w.in.e$r insert 0 $init\n"
  "  grid $w.in.l$r -row $r -column 0 -sticky w -padx 4 -pady 2\n"
  "  grid $w.in.e$r -row $r -column 1 -sticky ew -padx 4 -pady 2\n"
  "}\n"

  // A multi-line text input on grid row r that stretches with the tab, read back with getval.
  "proc mfield {w r label {init {}}} {\n"
  "  ttk::label $w.in.l$r -text $label\n"
  "  text $w.in.e$r -height 1 -width 30 -wrap char -background $::fbg -foreground $::fg -insertbackground $::fg -relief flat -borderwidth 4 -highlightthickness 0\n"
  "  $w.in.e$r insert 1.0 $init\n"
  "  grid $w.in.l$r -row $r -column 0 -sticky nw -padx 4 -pady 2\n"
  "  grid $w.in.e$r -row $r -column 1 -sticky nsew -padx 4 -pady 2\n"
  "  grid rowconfigure $w.in $r -weight 1\n"
  "}\n"

  // Read an input row, whether it is an entry or a text widget.
  "proc getval {w r} {\n"
  "  set p $w.in.e$r\n"
  "  if {[winfo class $p] eq {Text}} {return [$p get 1.0 end-1c]}\n"
  "  return [$p get]\n"
  "}\n"

  // A read-only result box in the lower part of the tab.
  "proc outbox {w} {\n"
  "  text $w.out -height 1 -width 30 -wrap char -state disabled -background $::fbg -foreground $::fg -relief flat -borderwidth 4 -highlightthickness 0\n"
  "  grid $w.out -row 1 -column 0 -sticky nsew -padx 4 -pady 4\n"
  "}\n"

  "proc show {w text} {\n"
  "  $w.out configure -state normal\n"
  "  $w.out delete 1.0 end\n"
  "  $w.out insert end $text\n"
  "  $w.out configure -state disabled\n"
  "}\n"

  // Run a command with the contents of the given entry rows as arguments, show the result or the error.
  "proc run {w cmd rows} {\n"
  "  set a {}\n"
  "  foreach r $rows {lappend a [getval $w $r]}\n"
  "  if {[catch {$cmd {*}$a} res]} {set res [join [list error: $res] { }]}\n"
  "  show $w $res\n"
  "}\n"

  // A labelled row of buttons: the row label, then text/command pairs.
  "proc buttons {w r label args} {\n"
  "  ttk::label $w.in.bl$r -text $label\n"
  "  ttk::frame $w.in.b$r\n"
  "  set i 0\n"
  "  foreach {t c} $args {\n"
  "    ttk::button $w.in.b$r.$i -text $t -command $c\n"
  "    pack $w.in.b$r.$i -side left -padx 2\n"
  "    incr i\n"
  "  }\n"
  "  grid $w.in.bl$r -row $r -column 0 -sticky w -padx 4 -pady 4\n"
  "  grid $w.in.b$r -row $r -column 1 -sticky w -padx 4 -pady 4\n"
  "}\n"

  // The Auto row: the Auto hash button plus a small updates entry. The entry keeps the e<row> naming (row 9, never gridded) so run and getval can read it, and is packed into the button row with -in.
  "proc autorow {w r cmd rows} {\n"
  "  buttons $w $r Auto {Auto hash} [list run $w $cmd $rows]\n"
  "  ttk::entry $w.in.e9 -width 10\n"
  "  $w.in.e9 insert 0 1\n"
  "  ttk::label $w.in.ul$r -text updates\n"
  "  pack $w.in.e9 -in $w.in.b$r -side left -padx {12 2}\n"
  "  pack $w.in.ul$r -in $w.in.b$r -side left -padx 2\n"
  "}\n"

  // Hash256
  "set w [tab Hash256]\n"
  "mfield $w 0 Message {hello ascon}\n"
  "autorow $w 1 ascon_hash256 {0 9}\n"
  "buttons $w 2 Manual Init [list run $w ascon_hash256_init {}] Update [list run $w ascon_hash256_update 0] Finalize [list run $w ascon_hash256_final {}]\n"
  "outbox $w\n"

  // XOF128
  "set w [tab XOF128]\n"
  "mfield $w 0 Message {hello ascon}\n"
  "field $w 1 {Output bytes} 32\n"
  "autorow $w 2 ascon_xof128 {0 1 9}\n"
  "buttons $w 3 Manual Init [list run $w ascon_xof128_init {}] Update [list run $w ascon_xof128_update 0] Squeeze [list run $w ascon_xof128_squeeze 1]\n"
  "outbox $w\n"

  // CXOF128
  "set w [tab CXOF128]\n"
  "mfield $w 0 Message {hello ascon}\n"
  "field $w 1 Customization {signing-key}\n"
  "field $w 2 {Output bytes} 32\n"
  "autorow $w 3 ascon_cxof128 {0 1 2 9}\n"
  "buttons $w 4 Manual Init [list run $w ascon_cxof128_init 1] Update [list run $w ascon_cxof128_update 0] Squeeze [list run $w ascon_cxof128_squeeze 2]\n"
  "outbox $w\n"

  // AEAD128: encrypt fills the ciphertext and tag fields so decrypt can be pressed straight after.
  "proc aead_encrypt_ui {w} {\n"
  "  if {[catch {ascon_aead128_encrypt [getval $w 0] [getval $w 1] [getval $w 2] [getval $w 3]} res]} {\n"
  "    show $w [join [list error: $res] { }]\n"
  "    return\n"
  "  }\n"
  "  $w.in.e4 delete 0 end\n"
  "  $w.in.e4 insert 0 [lindex $res 0]\n"
  "  $w.in.e5 delete 0 end\n"
  "  $w.in.e5 insert 0 [lindex $res 1]\n"
  "  show $w [join [list ciphertext: [lindex $res 0] tag: [lindex $res 1]] \\n]\n"
  "}\n"
  "set w [tab AEAD128]\n"
  "mfield $w 0 Plaintext {Secret message for Jane Doe.}\n"
  "field $w 1 {Associated data} {to: Jane}\n"
  "field $w 2 {Key (hex)} 000102030405060708090a0b0c0d0e0f\n"
  "field $w 3 {Nonce (hex)} 101112131415161718191a1b1c1d1e1f\n"
  "field $w 4 {Ciphertext (hex)}\n"
  "field $w 5 {Tag (hex)}\n"
  "buttons $w 6 {} Encrypt [list aead_encrypt_ui $w] Decrypt [list run $w ascon_aead128_decrypt {4 5 1 2 3}]\n"
  "outbox $w\n"

  // About: one read-only text box filling the whole tab. Edit the about lines below.
  "ttk::frame .nb.about -padding 4\n"
  ".nb add .nb.about -text About\n"
  "text .nb.about.t -wrap word -background $fbg -foreground $fg -relief flat -borderwidth 8 -highlightthickness 0\n"
  "pack .nb.about.t -fill both -expand 1\n"
  // Each about line adds one line of text. No backslashes needed.
  "proc about {line} {\n"
  "  .nb.about.t insert end $line\n"
  "  .nb.about.t insert end [format %c 10]\n"
  "}\n"
  "about {// pathcipher // a GUI for ascon-lib.}\n"
  "about {}\n"
  "about {Library: ascon-lib, a C implementation of NIST SP 800-232.}\n"
  "about {https://github.com/Iain-Donald/ascon-lib}\n"
  "about {}\n"
  "about {// Ciphers}\n"
  "about {Note to self: explain:}\n"
  "about {}\n"
  "about {Ascon-Hash256}\n"
  "about {Ascon-XOF128}\n"
  "about {Ascon-CXOF128}\n"
  "about {Ascon-AEAD128}\n"
  "about {}\n"
  "about {By Iain Donald.}\n"
  "about {License - BSD 3-clause. // Do as you wish, but without my name, and include the original license.}\n"
  "about {Version: 1.0a}\n"
  ".nb.about.t configure -state disabled\n";

int main(int argc, char **argv) {
  Tcl_Interp *interp;
  (void)argc;

  Tcl_FindExecutable(argv[0]);
  interp = Tcl_CreateInterp();
  if (Tcl_Init(interp) != TCL_OK || Tk_Init(interp) != TCL_OK) {
    fprintf(stderr, "Tcl/Tk init failed: %s\n", Tcl_GetStringResult(interp));
    return 1;
  }

  Tcl_CreateObjCommand(interp, "ascon_hash256", cmd_hash_oneshot, NULL, NULL);
  Tcl_CreateObjCommand(interp, "ascon_hash256_init", cmd_hash_init, NULL, NULL);
  Tcl_CreateObjCommand(interp, "ascon_hash256_update", cmd_hash_update, NULL, NULL);
  Tcl_CreateObjCommand(interp, "ascon_hash256_final", cmd_hash_final, NULL, NULL);
  Tcl_CreateObjCommand(interp, "ascon_xof128", cmd_xof_oneshot, NULL, NULL);
  Tcl_CreateObjCommand(interp, "ascon_xof128_init", cmd_xof_init, NULL, NULL);
  Tcl_CreateObjCommand(interp, "ascon_xof128_update", cmd_xof_update, NULL, NULL);
  Tcl_CreateObjCommand(interp, "ascon_xof128_squeeze", cmd_xof_squeeze, NULL, NULL);
  Tcl_CreateObjCommand(interp, "ascon_cxof128", cmd_cxof_oneshot, NULL, NULL);
  Tcl_CreateObjCommand(interp, "ascon_cxof128_init", cmd_cxof_init, NULL, NULL);
  Tcl_CreateObjCommand(interp, "ascon_cxof128_update", cmd_cxof_update, NULL, NULL);
  Tcl_CreateObjCommand(interp, "ascon_cxof128_squeeze", cmd_cxof_squeeze, NULL, NULL);
  Tcl_CreateObjCommand(interp, "ascon_aead128_encrypt", cmd_aead_encrypt, NULL, NULL);
  Tcl_CreateObjCommand(interp, "ascon_aead128_decrypt", cmd_aead_decrypt, NULL, NULL);

  if (Tcl_Eval(interp, gui_script) != TCL_OK) {
    fprintf(stderr, "GUI script error: %s\n", Tcl_GetStringResult(interp));
    return 1;
  }

  Tk_MainLoop();
  return 0;
}
