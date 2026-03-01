<?php
/**
 * PayzCore XenForo 2 Add-on Setup
 *
 * Registers the PayzCore payment provider in the xf_payment_provider table
 * on install and removes it on uninstall.
 *
 * @package    PayzCore
 * @author     PayzCore <support@payzcore.com>
 * @copyright  2026 PayzCore
 * @license    MIT
 * @link       https://payzcore.com
 */

namespace PayzCore;

use XF\AddOn\AbstractSetup;
use XF\AddOn\StepRunnerInstallTrait;
use XF\AddOn\StepRunnerUninstallTrait;
use XF\AddOn\StepRunnerUpgradeTrait;

class Setup extends AbstractSetup
{
    use StepRunnerInstallTrait;
    use StepRunnerUpgradeTrait;
    use StepRunnerUninstallTrait;

    /**
     * Install step 1: Register the payment provider.
     */
    public function installStep1()
    {
        $db = $this->db();

        foreach ($this->getPaymentProviders() as $providerId => $providerClass) {
            $db->insert('xf_payment_provider', [
                'provider_id'    => $providerId,
                'provider_class' => $providerClass,
                'addon_id'       => 'PayzCore',
            ], false, 'provider_class = VALUES(provider_class)');
        }
    }

    /**
     * Uninstall step 1: Remove the payment provider.
     */
    public function uninstallStep1()
    {
        $this->db()->delete('xf_payment_provider', "provider_id = 'payzCore'");
    }

    /**
     * Get the list of payment providers registered by this add-on.
     *
     * @return array
     */
    protected function getPaymentProviders()
    {
        return [
            'payzCore' => 'PayzCore:PayzCore',
        ];
    }
}
