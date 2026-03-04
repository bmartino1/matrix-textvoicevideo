// Jitsi Meet custom overrides — reference/custom-config.js
// Deployed to: data/jitsi/web/custom-config.js
// Placeholders replaced by setup.sh via tmpl_subst.
var defined_config = typeof config === 'object' ? config : {};
var custom_config = {
    hosts: {
        anonymousdomain: 'guest.__MEET_DOMAIN__'
    },
    hideLoginButton: true,
    disableDeepLinking: true,
    prejoinConfig: { enabled: true },
    toolbarButtons: [
        'camera', 'chat', 'desktop', 'filmstrip', 'fullscreen',
        'hangup', 'microphone', 'participants-pane', 'raisehand',
        'select-background', 'settings', 'tileview', 'toggle-camera'
    ],
    disableThirdPartyRequests: true,
    analytics: { disabled: true },
    giphy: { enabled: false }
};
var merged_config = Object.assign({}, defined_config, custom_config);
