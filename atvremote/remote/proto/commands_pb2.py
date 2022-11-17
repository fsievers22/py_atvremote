# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: atvremote/remote/proto/commands.proto
"""Generated protocol buffer code."""
from google.protobuf.internal import builder as _builder
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n%atvremote/remote/proto/commands.proto\".\n\x1aRemoteAppLinkLaunchRequest\x12\x10\n\x08\x61pp_link\x18\x01 \x01(\t\"!\n\x1fRemoteResetPreferredAudioDevice\"\x1f\n\x1dRemoteSetPreferredAudioDevice\"\x19\n\x17RemoteAdjustVolumeLevel\"\xb4\x01\n\x14RemoteSetVolumeLevel\x12\x10\n\x08unknown1\x18\x01 \x01(\r\x12\x10\n\x08unknown2\x18\x02 \x01(\r\x12\x14\n\x0cplayer_model\x18\x03 \x01(\t\x12\x10\n\x08unknown4\x18\x04 \x01(\r\x12\x10\n\x08unknown5\x18\x05 \x01(\r\x12\x12\n\nvolume_max\x18\x06 \x01(\r\x12\x14\n\x0cvolume_level\x18\x07 \x01(\r\x12\x14\n\x0cvolume_muted\x18\x08 \x01(\x08\"\x1e\n\x0bRemoteStart\x12\x0f\n\x07started\x18\x01 \x01(\x08\"\x10\n\x0eRemoteVoiceEnd\"\x14\n\x12RemoteVoicePayload\"\x12\n\x10RemoteVoiceBegin\"v\n\x15RemoteTextFieldStatus\x12\x15\n\rcounter_field\x18\x01 \x01(\x05\x12\r\n\x05value\x18\x02 \x01(\t\x12\r\n\x05start\x18\x03 \x01(\x05\x12\x0b\n\x03\x65nd\x18\x04 \x01(\x05\x12\x0c\n\x04int5\x18\x05 \x01(\x05\x12\r\n\x05label\x18\x06 \x01(\t\"P\n\x14RemoteImeShowRequest\x12\x38\n\x18remote_text_field_status\x18\x02 \x01(\x0b\x32\x16.RemoteTextFieldStatus\" \n\x0eRemoteEditInfo\x12\x0e\n\x06insert\x18\x02 \x01(\x05\"d\n\x12RemoteImeBatchEdit\x12\x13\n\x0bime_counter\x18\x01 \x01(\x05\x12\x15\n\rfield_counter\x18\x02 \x01(\x05\x12\"\n\tedit_info\x18\x03 \x01(\x0b\x32\x0f.RemoteEditInfo\"\x99\x01\n\rRemoteAppInfo\x12\x0f\n\x07\x63ounter\x18\x01 \x01(\x05\x12\x0c\n\x04int2\x18\x02 \x01(\x05\x12\x0c\n\x04int3\x18\x03 \x01(\x05\x12\x0c\n\x04int4\x18\x04 \x01(\t\x12\x0c\n\x04int7\x18\x07 \x01(\x05\x12\x0c\n\x04int8\x18\x08 \x01(\x05\x12\r\n\x05label\x18\n \x01(\t\x12\x13\n\x0b\x61pp_package\x18\x0c \x01(\t\x12\r\n\x05int13\x18\r \x01(\x05\"i\n\x12RemoteImeKeyInject\x12 \n\x08\x61pp_info\x18\x01 \x01(\x0b\x32\x0e.RemoteAppInfo\x12\x31\n\x11text_field_status\x18\x02 \x01(\x0b\x32\x16.RemoteTextFieldStatus\"X\n\x0fRemoteKeyInject\x12 \n\x08key_code\x18\x01 \x01(\x0e\x32\x0e.RemoteKeyCode\x12#\n\tdirection\x18\x02 \x01(\x0e\x32\x10.RemoteDirection\"\"\n\x12RemotePingResponse\x12\x0c\n\x04val1\x18\x01 \x01(\x05\"/\n\x11RemotePingRequest\x12\x0c\n\x04val1\x18\x01 \x01(\x05\x12\x0c\n\x04val2\x18\x02 \x01(\x05\"!\n\x0fRemoteSetActive\x12\x0e\n\x06\x61\x63tive\x18\x01 \x01(\x05\"\x80\x01\n\x10RemoteDeviceInfo\x12\r\n\x05model\x18\x01 \x01(\t\x12\x0e\n\x06vendor\x18\x02 \x01(\t\x12\x10\n\x08unknown1\x18\x03 \x01(\x05\x12\x10\n\x08unknown2\x18\x04 \x01(\t\x12\x14\n\x0cpackage_name\x18\x05 \x01(\t\x12\x13\n\x0b\x61pp_version\x18\x06 \x01(\t\"H\n\x0fRemoteConfigure\x12\r\n\x05\x63ode1\x18\x01 \x01(\x05\x12&\n\x0b\x64\x65vice_info\x18\x02 \x01(\x0b\x32\x11.RemoteDeviceInfo\"=\n\x0bRemoteError\x12\r\n\x05value\x18\x01 \x01(\x08\x12\x1f\n\x07message\x18\x02 \x01(\x0b\x32\x0e.RemoteMessage\"\xc3\x07\n\rRemoteMessage\x12*\n\x10remote_configure\x18\x01 \x01(\x0b\x32\x10.RemoteConfigure\x12+\n\x11remote_set_active\x18\x02 \x01(\x0b\x32\x10.RemoteSetActive\x12\"\n\x0cremote_error\x18\x03 \x01(\x0b\x32\x0c.RemoteError\x12/\n\x13remote_ping_request\x18\x08 \x01(\x0b\x32\x12.RemotePingRequest\x12\x31\n\x14remote_ping_response\x18\t \x01(\x0b\x32\x13.RemotePingResponse\x12+\n\x11remote_key_inject\x18\n \x01(\x0b\x32\x10.RemoteKeyInject\x12\x32\n\x15remote_ime_key_inject\x18\x14 \x01(\x0b\x32\x13.RemoteImeKeyInject\x12\x32\n\x15remote_ime_batch_edit\x18\x15 \x01(\x0b\x32\x13.RemoteImeBatchEdit\x12\x36\n\x17remote_ime_show_request\x18\x16 \x01(\x0b\x32\x15.RemoteImeShowRequest\x12-\n\x12remote_voice_begin\x18\x1e \x01(\x0b\x32\x11.RemoteVoiceBegin\x12\x31\n\x14remote_voice_payload\x18\x1f \x01(\x0b\x32\x13.RemoteVoicePayload\x12)\n\x10remote_voice_end\x18  \x01(\x0b\x32\x0f.RemoteVoiceEnd\x12\"\n\x0cremote_start\x18( \x01(\x0b\x32\x0c.RemoteStart\x12\x36\n\x17remote_set_volume_level\x18\x32 \x01(\x0b\x32\x15.RemoteSetVolumeLevel\x12<\n\x1aremote_adjust_volume_level\x18\x33 \x01(\x0b\x32\x18.RemoteAdjustVolumeLevel\x12I\n!remote_set_preferred_audio_device\x18< \x01(\x0b\x32\x1e.RemoteSetPreferredAudioDevice\x12M\n#remote_reset_preferred_audio_device\x18= \x01(\x0b\x32 .RemoteResetPreferredAudioDevice\x12\x43\n\x1eremote_app_link_launch_request\x18Z \x01(\x0b\x32\x1b.RemoteAppLinkLaunchRequest*\xe7\x37\n\rRemoteKeyCode\x12\x13\n\x0fKEYCODE_UNKNOWN\x10\x00\x12\x15\n\x11KEYCODE_SOFT_LEFT\x10\x01\x12\x16\n\x12KEYCODE_SOFT_RIGHT\x10\x02\x12\x10\n\x0cKEYCODE_HOME\x10\x03\x12\x10\n\x0cKEYCODE_BACK\x10\x04\x12\x10\n\x0cKEYCODE_CALL\x10\x05\x12\x13\n\x0fKEYCODE_ENDCALL\x10\x06\x12\r\n\tKEYCODE_0\x10\x07\x12\r\n\tKEYCODE_1\x10\x08\x12\r\n\tKEYCODE_2\x10\t\x12\r\n\tKEYCODE_3\x10\n\x12\r\n\tKEYCODE_4\x10\x0b\x12\r\n\tKEYCODE_5\x10\x0c\x12\r\n\tKEYCODE_6\x10\r\x12\r\n\tKEYCODE_7\x10\x0e\x12\r\n\tKEYCODE_8\x10\x0f\x12\r\n\tKEYCODE_9\x10\x10\x12\x10\n\x0cKEYCODE_STAR\x10\x11\x12\x11\n\rKEYCODE_POUND\x10\x12\x12\x13\n\x0fKEYCODE_DPAD_UP\x10\x13\x12\x15\n\x11KEYCODE_DPAD_DOWN\x10\x14\x12\x15\n\x11KEYCODE_DPAD_LEFT\x10\x15\x12\x16\n\x12KEYCODE_DPAD_RIGHT\x10\x16\x12\x17\n\x13KEYCODE_DPAD_CENTER\x10\x17\x12\x15\n\x11KEYCODE_VOLUME_UP\x10\x18\x12\x17\n\x13KEYCODE_VOLUME_DOWN\x10\x19\x12\x11\n\rKEYCODE_POWER\x10\x1a\x12\x12\n\x0eKEYCODE_CAMERA\x10\x1b\x12\x11\n\rKEYCODE_CLEAR\x10\x1c\x12\r\n\tKEYCODE_A\x10\x1d\x12\r\n\tKEYCODE_B\x10\x1e\x12\r\n\tKEYCODE_C\x10\x1f\x12\r\n\tKEYCODE_D\x10 \x12\r\n\tKEYCODE_E\x10!\x12\r\n\tKEYCODE_F\x10\"\x12\r\n\tKEYCODE_G\x10#\x12\r\n\tKEYCODE_H\x10$\x12\r\n\tKEYCODE_I\x10%\x12\r\n\tKEYCODE_J\x10&\x12\r\n\tKEYCODE_K\x10\'\x12\r\n\tKEYCODE_L\x10(\x12\r\n\tKEYCODE_M\x10)\x12\r\n\tKEYCODE_N\x10*\x12\r\n\tKEYCODE_O\x10+\x12\r\n\tKEYCODE_P\x10,\x12\r\n\tKEYCODE_Q\x10-\x12\r\n\tKEYCODE_R\x10.\x12\r\n\tKEYCODE_S\x10/\x12\r\n\tKEYCODE_T\x10\x30\x12\r\n\tKEYCODE_U\x10\x31\x12\r\n\tKEYCODE_V\x10\x32\x12\r\n\tKEYCODE_W\x10\x33\x12\r\n\tKEYCODE_X\x10\x34\x12\r\n\tKEYCODE_Y\x10\x35\x12\r\n\tKEYCODE_Z\x10\x36\x12\x11\n\rKEYCODE_COMMA\x10\x37\x12\x12\n\x0eKEYCODE_PERIOD\x10\x38\x12\x14\n\x10KEYCODE_ALT_LEFT\x10\x39\x12\x15\n\x11KEYCODE_ALT_RIGHT\x10:\x12\x16\n\x12KEYCODE_SHIFT_LEFT\x10;\x12\x17\n\x13KEYCODE_SHIFT_RIGHT\x10<\x12\x0f\n\x0bKEYCODE_TAB\x10=\x12\x11\n\rKEYCODE_SPACE\x10>\x12\x0f\n\x0bKEYCODE_SYM\x10?\x12\x14\n\x10KEYCODE_EXPLORER\x10@\x12\x14\n\x10KEYCODE_ENVELOPE\x10\x41\x12\x11\n\rKEYCODE_ENTER\x10\x42\x12\x0f\n\x0bKEYCODE_DEL\x10\x43\x12\x11\n\rKEYCODE_GRAVE\x10\x44\x12\x11\n\rKEYCODE_MINUS\x10\x45\x12\x12\n\x0eKEYCODE_EQUALS\x10\x46\x12\x18\n\x14KEYCODE_LEFT_BRACKET\x10G\x12\x19\n\x15KEYCODE_RIGHT_BRACKET\x10H\x12\x15\n\x11KEYCODE_BACKSLASH\x10I\x12\x15\n\x11KEYCODE_SEMICOLON\x10J\x12\x16\n\x12KEYCODE_APOSTROPHE\x10K\x12\x11\n\rKEYCODE_SLASH\x10L\x12\x0e\n\nKEYCODE_AT\x10M\x12\x0f\n\x0bKEYCODE_NUM\x10N\x12\x17\n\x13KEYCODE_HEADSETHOOK\x10O\x12\x11\n\rKEYCODE_FOCUS\x10P\x12\x10\n\x0cKEYCODE_PLUS\x10Q\x12\x10\n\x0cKEYCODE_MENU\x10R\x12\x18\n\x14KEYCODE_NOTIFICATION\x10S\x12\x12\n\x0eKEYCODE_SEARCH\x10T\x12\x1c\n\x18KEYCODE_MEDIA_PLAY_PAUSE\x10U\x12\x16\n\x12KEYCODE_MEDIA_STOP\x10V\x12\x16\n\x12KEYCODE_MEDIA_NEXT\x10W\x12\x1a\n\x16KEYCODE_MEDIA_PREVIOUS\x10X\x12\x18\n\x14KEYCODE_MEDIA_REWIND\x10Y\x12\x1e\n\x1aKEYCODE_MEDIA_FAST_FORWARD\x10Z\x12\x10\n\x0cKEYCODE_MUTE\x10[\x12\x13\n\x0fKEYCODE_PAGE_UP\x10\\\x12\x15\n\x11KEYCODE_PAGE_DOWN\x10]\x12\x17\n\x13KEYCODE_PICTSYMBOLS\x10^\x12\x1a\n\x16KEYCODE_SWITCH_CHARSET\x10_\x12\x14\n\x10KEYCODE_BUTTON_A\x10`\x12\x14\n\x10KEYCODE_BUTTON_B\x10\x61\x12\x14\n\x10KEYCODE_BUTTON_C\x10\x62\x12\x14\n\x10KEYCODE_BUTTON_X\x10\x63\x12\x14\n\x10KEYCODE_BUTTON_Y\x10\x64\x12\x14\n\x10KEYCODE_BUTTON_Z\x10\x65\x12\x15\n\x11KEYCODE_BUTTON_L1\x10\x66\x12\x15\n\x11KEYCODE_BUTTON_R1\x10g\x12\x15\n\x11KEYCODE_BUTTON_L2\x10h\x12\x15\n\x11KEYCODE_BUTTON_R2\x10i\x12\x19\n\x15KEYCODE_BUTTON_THUMBL\x10j\x12\x19\n\x15KEYCODE_BUTTON_THUMBR\x10k\x12\x18\n\x14KEYCODE_BUTTON_START\x10l\x12\x19\n\x15KEYCODE_BUTTON_SELECT\x10m\x12\x17\n\x13KEYCODE_BUTTON_MODE\x10n\x12\x12\n\x0eKEYCODE_ESCAPE\x10o\x12\x17\n\x13KEYCODE_FORWARD_DEL\x10p\x12\x15\n\x11KEYCODE_CTRL_LEFT\x10q\x12\x16\n\x12KEYCODE_CTRL_RIGHT\x10r\x12\x15\n\x11KEYCODE_CAPS_LOCK\x10s\x12\x17\n\x13KEYCODE_SCROLL_LOCK\x10t\x12\x15\n\x11KEYCODE_META_LEFT\x10u\x12\x16\n\x12KEYCODE_META_RIGHT\x10v\x12\x14\n\x10KEYCODE_FUNCTION\x10w\x12\x11\n\rKEYCODE_SYSRQ\x10x\x12\x11\n\rKEYCODE_BREAK\x10y\x12\x15\n\x11KEYCODE_MOVE_HOME\x10z\x12\x14\n\x10KEYCODE_MOVE_END\x10{\x12\x12\n\x0eKEYCODE_INSERT\x10|\x12\x13\n\x0fKEYCODE_FORWARD\x10}\x12\x16\n\x12KEYCODE_MEDIA_PLAY\x10~\x12\x17\n\x13KEYCODE_MEDIA_PAUSE\x10\x7f\x12\x18\n\x13KEYCODE_MEDIA_CLOSE\x10\x80\x01\x12\x18\n\x13KEYCODE_MEDIA_EJECT\x10\x81\x01\x12\x19\n\x14KEYCODE_MEDIA_RECORD\x10\x82\x01\x12\x0f\n\nKEYCODE_F1\x10\x83\x01\x12\x0f\n\nKEYCODE_F2\x10\x84\x01\x12\x0f\n\nKEYCODE_F3\x10\x85\x01\x12\x0f\n\nKEYCODE_F4\x10\x86\x01\x12\x0f\n\nKEYCODE_F5\x10\x87\x01\x12\x0f\n\nKEYCODE_F6\x10\x88\x01\x12\x0f\n\nKEYCODE_F7\x10\x89\x01\x12\x0f\n\nKEYCODE_F8\x10\x8a\x01\x12\x0f\n\nKEYCODE_F9\x10\x8b\x01\x12\x10\n\x0bKEYCODE_F10\x10\x8c\x01\x12\x10\n\x0bKEYCODE_F11\x10\x8d\x01\x12\x10\n\x0bKEYCODE_F12\x10\x8e\x01\x12\x15\n\x10KEYCODE_NUM_LOCK\x10\x8f\x01\x12\x15\n\x10KEYCODE_NUMPAD_0\x10\x90\x01\x12\x15\n\x10KEYCODE_NUMPAD_1\x10\x91\x01\x12\x15\n\x10KEYCODE_NUMPAD_2\x10\x92\x01\x12\x15\n\x10KEYCODE_NUMPAD_3\x10\x93\x01\x12\x15\n\x10KEYCODE_NUMPAD_4\x10\x94\x01\x12\x15\n\x10KEYCODE_NUMPAD_5\x10\x95\x01\x12\x15\n\x10KEYCODE_NUMPAD_6\x10\x96\x01\x12\x15\n\x10KEYCODE_NUMPAD_7\x10\x97\x01\x12\x15\n\x10KEYCODE_NUMPAD_8\x10\x98\x01\x12\x15\n\x10KEYCODE_NUMPAD_9\x10\x99\x01\x12\x1a\n\x15KEYCODE_NUMPAD_DIVIDE\x10\x9a\x01\x12\x1c\n\x17KEYCODE_NUMPAD_MULTIPLY\x10\x9b\x01\x12\x1c\n\x17KEYCODE_NUMPAD_SUBTRACT\x10\x9c\x01\x12\x17\n\x12KEYCODE_NUMPAD_ADD\x10\x9d\x01\x12\x17\n\x12KEYCODE_NUMPAD_DOT\x10\x9e\x01\x12\x19\n\x14KEYCODE_NUMPAD_COMMA\x10\x9f\x01\x12\x19\n\x14KEYCODE_NUMPAD_ENTER\x10\xa0\x01\x12\x1a\n\x15KEYCODE_NUMPAD_EQUALS\x10\xa1\x01\x12\x1e\n\x19KEYCODE_NUMPAD_LEFT_PAREN\x10\xa2\x01\x12\x1f\n\x1aKEYCODE_NUMPAD_RIGHT_PAREN\x10\xa3\x01\x12\x18\n\x13KEYCODE_VOLUME_MUTE\x10\xa4\x01\x12\x11\n\x0cKEYCODE_INFO\x10\xa5\x01\x12\x17\n\x12KEYCODE_CHANNEL_UP\x10\xa6\x01\x12\x19\n\x14KEYCODE_CHANNEL_DOWN\x10\xa7\x01\x12\x14\n\x0fKEYCODE_ZOOM_IN\x10\xa8\x01\x12\x15\n\x10KEYCODE_ZOOM_OUT\x10\xa9\x01\x12\x0f\n\nKEYCODE_TV\x10\xaa\x01\x12\x13\n\x0eKEYCODE_WINDOW\x10\xab\x01\x12\x12\n\rKEYCODE_GUIDE\x10\xac\x01\x12\x10\n\x0bKEYCODE_DVR\x10\xad\x01\x12\x15\n\x10KEYCODE_BOOKMARK\x10\xae\x01\x12\x15\n\x10KEYCODE_CAPTIONS\x10\xaf\x01\x12\x15\n\x10KEYCODE_SETTINGS\x10\xb0\x01\x12\x15\n\x10KEYCODE_TV_POWER\x10\xb1\x01\x12\x15\n\x10KEYCODE_TV_INPUT\x10\xb2\x01\x12\x16\n\x11KEYCODE_STB_POWER\x10\xb3\x01\x12\x16\n\x11KEYCODE_STB_INPUT\x10\xb4\x01\x12\x16\n\x11KEYCODE_AVR_POWER\x10\xb5\x01\x12\x16\n\x11KEYCODE_AVR_INPUT\x10\xb6\x01\x12\x15\n\x10KEYCODE_PROG_RED\x10\xb7\x01\x12\x17\n\x12KEYCODE_PROG_GREEN\x10\xb8\x01\x12\x18\n\x13KEYCODE_PROG_YELLOW\x10\xb9\x01\x12\x16\n\x11KEYCODE_PROG_BLUE\x10\xba\x01\x12\x17\n\x12KEYCODE_APP_SWITCH\x10\xbb\x01\x12\x15\n\x10KEYCODE_BUTTON_1\x10\xbc\x01\x12\x15\n\x10KEYCODE_BUTTON_2\x10\xbd\x01\x12\x15\n\x10KEYCODE_BUTTON_3\x10\xbe\x01\x12\x15\n\x10KEYCODE_BUTTON_4\x10\xbf\x01\x12\x15\n\x10KEYCODE_BUTTON_5\x10\xc0\x01\x12\x15\n\x10KEYCODE_BUTTON_6\x10\xc1\x01\x12\x15\n\x10KEYCODE_BUTTON_7\x10\xc2\x01\x12\x15\n\x10KEYCODE_BUTTON_8\x10\xc3\x01\x12\x15\n\x10KEYCODE_BUTTON_9\x10\xc4\x01\x12\x16\n\x11KEYCODE_BUTTON_10\x10\xc5\x01\x12\x16\n\x11KEYCODE_BUTTON_11\x10\xc6\x01\x12\x16\n\x11KEYCODE_BUTTON_12\x10\xc7\x01\x12\x16\n\x11KEYCODE_BUTTON_13\x10\xc8\x01\x12\x16\n\x11KEYCODE_BUTTON_14\x10\xc9\x01\x12\x16\n\x11KEYCODE_BUTTON_15\x10\xca\x01\x12\x16\n\x11KEYCODE_BUTTON_16\x10\xcb\x01\x12\x1c\n\x17KEYCODE_LANGUAGE_SWITCH\x10\xcc\x01\x12\x18\n\x13KEYCODE_MANNER_MODE\x10\xcd\x01\x12\x14\n\x0fKEYCODE_3D_MODE\x10\xce\x01\x12\x15\n\x10KEYCODE_CONTACTS\x10\xcf\x01\x12\x15\n\x10KEYCODE_CALENDAR\x10\xd0\x01\x12\x12\n\rKEYCODE_MUSIC\x10\xd1\x01\x12\x17\n\x12KEYCODE_CALCULATOR\x10\xd2\x01\x12\x1c\n\x17KEYCODE_ZENKAKU_HANKAKU\x10\xd3\x01\x12\x11\n\x0cKEYCODE_EISU\x10\xd4\x01\x12\x15\n\x10KEYCODE_MUHENKAN\x10\xd5\x01\x12\x13\n\x0eKEYCODE_HENKAN\x10\xd6\x01\x12\x1e\n\x19KEYCODE_KATAKANA_HIRAGANA\x10\xd7\x01\x12\x10\n\x0bKEYCODE_YEN\x10\xd8\x01\x12\x0f\n\nKEYCODE_RO\x10\xd9\x01\x12\x11\n\x0cKEYCODE_KANA\x10\xda\x01\x12\x13\n\x0eKEYCODE_ASSIST\x10\xdb\x01\x12\x1c\n\x17KEYCODE_BRIGHTNESS_DOWN\x10\xdc\x01\x12\x1a\n\x15KEYCODE_BRIGHTNESS_UP\x10\xdd\x01\x12\x1e\n\x19KEYCODE_MEDIA_AUDIO_TRACK\x10\xde\x01\x12\x12\n\rKEYCODE_SLEEP\x10\xdf\x01\x12\x13\n\x0eKEYCODE_WAKEUP\x10\xe0\x01\x12\x14\n\x0fKEYCODE_PAIRING\x10\xe1\x01\x12\x1b\n\x16KEYCODE_MEDIA_TOP_MENU\x10\xe2\x01\x12\x0f\n\nKEYCODE_11\x10\xe3\x01\x12\x0f\n\nKEYCODE_12\x10\xe4\x01\x12\x19\n\x14KEYCODE_LAST_CHANNEL\x10\xe5\x01\x12\x1c\n\x17KEYCODE_TV_DATA_SERVICE\x10\xe6\x01\x12\x19\n\x14KEYCODE_VOICE_ASSIST\x10\xe7\x01\x12\x1d\n\x18KEYCODE_TV_RADIO_SERVICE\x10\xe8\x01\x12\x18\n\x13KEYCODE_TV_TELETEXT\x10\xe9\x01\x12\x1c\n\x17KEYCODE_TV_NUMBER_ENTRY\x10\xea\x01\x12\"\n\x1dKEYCODE_TV_TERRESTRIAL_ANALOG\x10\xeb\x01\x12#\n\x1eKEYCODE_TV_TERRESTRIAL_DIGITAL\x10\xec\x01\x12\x19\n\x14KEYCODE_TV_SATELLITE\x10\xed\x01\x12\x1c\n\x17KEYCODE_TV_SATELLITE_BS\x10\xee\x01\x12\x1c\n\x17KEYCODE_TV_SATELLITE_CS\x10\xef\x01\x12!\n\x1cKEYCODE_TV_SATELLITE_SERVICE\x10\xf0\x01\x12\x17\n\x12KEYCODE_TV_NETWORK\x10\xf1\x01\x12\x1d\n\x18KEYCODE_TV_ANTENNA_CABLE\x10\xf2\x01\x12\x1c\n\x17KEYCODE_TV_INPUT_HDMI_1\x10\xf3\x01\x12\x1c\n\x17KEYCODE_TV_INPUT_HDMI_2\x10\xf4\x01\x12\x1c\n\x17KEYCODE_TV_INPUT_HDMI_3\x10\xf5\x01\x12\x1c\n\x17KEYCODE_TV_INPUT_HDMI_4\x10\xf6\x01\x12!\n\x1cKEYCODE_TV_INPUT_COMPOSITE_1\x10\xf7\x01\x12!\n\x1cKEYCODE_TV_INPUT_COMPOSITE_2\x10\xf8\x01\x12!\n\x1cKEYCODE_TV_INPUT_COMPONENT_1\x10\xf9\x01\x12!\n\x1cKEYCODE_TV_INPUT_COMPONENT_2\x10\xfa\x01\x12\x1b\n\x16KEYCODE_TV_INPUT_VGA_1\x10\xfb\x01\x12!\n\x1cKEYCODE_TV_AUDIO_DESCRIPTION\x10\xfc\x01\x12(\n#KEYCODE_TV_AUDIO_DESCRIPTION_MIX_UP\x10\xfd\x01\x12*\n%KEYCODE_TV_AUDIO_DESCRIPTION_MIX_DOWN\x10\xfe\x01\x12\x19\n\x14KEYCODE_TV_ZOOM_MODE\x10\xff\x01\x12\x1d\n\x18KEYCODE_TV_CONTENTS_MENU\x10\x80\x02\x12\"\n\x1dKEYCODE_TV_MEDIA_CONTEXT_MENU\x10\x81\x02\x12!\n\x1cKEYCODE_TV_TIMER_PROGRAMMING\x10\x82\x02\x12\x11\n\x0cKEYCODE_HELP\x10\x83\x02\x12\x1e\n\x19KEYCODE_NAVIGATE_PREVIOUS\x10\x84\x02\x12\x1a\n\x15KEYCODE_NAVIGATE_NEXT\x10\x85\x02\x12\x18\n\x13KEYCODE_NAVIGATE_IN\x10\x86\x02\x12\x19\n\x14KEYCODE_NAVIGATE_OUT\x10\x87\x02\x12\x19\n\x14KEYCODE_STEM_PRIMARY\x10\x88\x02\x12\x13\n\x0eKEYCODE_STEM_1\x10\x89\x02\x12\x13\n\x0eKEYCODE_STEM_2\x10\x8a\x02\x12\x13\n\x0eKEYCODE_STEM_3\x10\x8b\x02\x12\x19\n\x14KEYCODE_DPAD_UP_LEFT\x10\x8c\x02\x12\x1b\n\x16KEYCODE_DPAD_DOWN_LEFT\x10\x8d\x02\x12\x1a\n\x15KEYCODE_DPAD_UP_RIGHT\x10\x8e\x02\x12\x1c\n\x17KEYCODE_DPAD_DOWN_RIGHT\x10\x8f\x02\x12\x1f\n\x1aKEYCODE_MEDIA_SKIP_FORWARD\x10\x90\x02\x12 \n\x1bKEYCODE_MEDIA_SKIP_BACKWARD\x10\x91\x02\x12\x1f\n\x1aKEYCODE_MEDIA_STEP_FORWARD\x10\x92\x02\x12 \n\x1bKEYCODE_MEDIA_STEP_BACKWARD\x10\x93\x02\x12\x17\n\x12KEYCODE_SOFT_SLEEP\x10\x94\x02\x12\x10\n\x0bKEYCODE_CUT\x10\x95\x02\x12\x11\n\x0cKEYCODE_COPY\x10\x96\x02\x12\x12\n\rKEYCODE_PASTE\x10\x97\x02\x12!\n\x1cKEYCODE_SYSTEM_NAVIGATION_UP\x10\x98\x02\x12#\n\x1eKEYCODE_SYSTEM_NAVIGATION_DOWN\x10\x99\x02\x12#\n\x1eKEYCODE_SYSTEM_NAVIGATION_LEFT\x10\x9a\x02\x12$\n\x1fKEYCODE_SYSTEM_NAVIGATION_RIGHT\x10\x9b\x02\x12\x15\n\x10KEYCODE_ALL_APPS\x10\x9c\x02\x12\x14\n\x0fKEYCODE_REFRESH\x10\x9d\x02\x12\x16\n\x11KEYCODE_THUMBS_UP\x10\x9e\x02\x12\x18\n\x13KEYCODE_THUMBS_DOWN\x10\x9f\x02\x12\x1b\n\x16KEYCODE_PROFILE_SWITCH\x10\xa0\x02\x12\x18\n\x13KEYCODE_VIDEO_APP_1\x10\xa1\x02\x12\x18\n\x13KEYCODE_VIDEO_APP_2\x10\xa2\x02\x12\x18\n\x13KEYCODE_VIDEO_APP_3\x10\xa3\x02\x12\x18\n\x13KEYCODE_VIDEO_APP_4\x10\xa4\x02\x12\x18\n\x13KEYCODE_VIDEO_APP_5\x10\xa5\x02\x12\x18\n\x13KEYCODE_VIDEO_APP_6\x10\xa6\x02\x12\x18\n\x13KEYCODE_VIDEO_APP_7\x10\xa7\x02\x12\x18\n\x13KEYCODE_VIDEO_APP_8\x10\xa8\x02\x12\x1b\n\x16KEYCODE_FEATURED_APP_1\x10\xa9\x02\x12\x1b\n\x16KEYCODE_FEATURED_APP_2\x10\xaa\x02\x12\x1b\n\x16KEYCODE_FEATURED_APP_3\x10\xab\x02\x12\x1b\n\x16KEYCODE_FEATURED_APP_4\x10\xac\x02\x12\x17\n\x12KEYCODE_DEMO_APP_1\x10\xad\x02\x12\x17\n\x12KEYCODE_DEMO_APP_2\x10\xae\x02\x12\x17\n\x12KEYCODE_DEMO_APP_3\x10\xaf\x02\x12\x17\n\x12KEYCODE_DEMO_APP_4\x10\xb0\x02*Q\n\x0fRemoteDirection\x12\x15\n\x11UNKNOWN_DIRECTION\x10\x00\x12\x0e\n\nSTART_LONG\x10\x01\x12\x0c\n\x08\x45ND_LONG\x10\x02\x12\t\n\x05SHORT\x10\x03\x62\x06proto3')

_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, globals())
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'atvremote.remote.proto.commands_pb2', globals())
if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  _REMOTEKEYCODE._serialized_start=2505
  _REMOTEKEYCODE._serialized_end=9648
  _REMOTEDIRECTION._serialized_start=9650
  _REMOTEDIRECTION._serialized_end=9731
  _REMOTEAPPLINKLAUNCHREQUEST._serialized_start=41
  _REMOTEAPPLINKLAUNCHREQUEST._serialized_end=87
  _REMOTERESETPREFERREDAUDIODEVICE._serialized_start=89
  _REMOTERESETPREFERREDAUDIODEVICE._serialized_end=122
  _REMOTESETPREFERREDAUDIODEVICE._serialized_start=124
  _REMOTESETPREFERREDAUDIODEVICE._serialized_end=155
  _REMOTEADJUSTVOLUMELEVEL._serialized_start=157
  _REMOTEADJUSTVOLUMELEVEL._serialized_end=182
  _REMOTESETVOLUMELEVEL._serialized_start=185
  _REMOTESETVOLUMELEVEL._serialized_end=365
  _REMOTESTART._serialized_start=367
  _REMOTESTART._serialized_end=397
  _REMOTEVOICEEND._serialized_start=399
  _REMOTEVOICEEND._serialized_end=415
  _REMOTEVOICEPAYLOAD._serialized_start=417
  _REMOTEVOICEPAYLOAD._serialized_end=437
  _REMOTEVOICEBEGIN._serialized_start=439
  _REMOTEVOICEBEGIN._serialized_end=457
  _REMOTETEXTFIELDSTATUS._serialized_start=459
  _REMOTETEXTFIELDSTATUS._serialized_end=577
  _REMOTEIMESHOWREQUEST._serialized_start=579
  _REMOTEIMESHOWREQUEST._serialized_end=659
  _REMOTEEDITINFO._serialized_start=661
  _REMOTEEDITINFO._serialized_end=693
  _REMOTEIMEBATCHEDIT._serialized_start=695
  _REMOTEIMEBATCHEDIT._serialized_end=795
  _REMOTEAPPINFO._serialized_start=798
  _REMOTEAPPINFO._serialized_end=951
  _REMOTEIMEKEYINJECT._serialized_start=953
  _REMOTEIMEKEYINJECT._serialized_end=1058
  _REMOTEKEYINJECT._serialized_start=1060
  _REMOTEKEYINJECT._serialized_end=1148
  _REMOTEPINGRESPONSE._serialized_start=1150
  _REMOTEPINGRESPONSE._serialized_end=1184
  _REMOTEPINGREQUEST._serialized_start=1186
  _REMOTEPINGREQUEST._serialized_end=1233
  _REMOTESETACTIVE._serialized_start=1235
  _REMOTESETACTIVE._serialized_end=1268
  _REMOTEDEVICEINFO._serialized_start=1271
  _REMOTEDEVICEINFO._serialized_end=1399
  _REMOTECONFIGURE._serialized_start=1401
  _REMOTECONFIGURE._serialized_end=1473
  _REMOTEERROR._serialized_start=1475
  _REMOTEERROR._serialized_end=1536
  _REMOTEMESSAGE._serialized_start=1539
  _REMOTEMESSAGE._serialized_end=2502
# @@protoc_insertion_point(module_scope)
