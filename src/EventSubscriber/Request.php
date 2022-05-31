<?php

namespace Drupal\abuse_ipdb\EventSubscriber;

use Drupal\Core\KeyValueStore\KeyValueExpirableFactory;
use GuzzleHttp\Client;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\KernelEvents;

class Request implements EventSubscriberInterface {
  /**
   * The key value expirable service.
   *
   * @var KeyValueExpirableFactory $keyValueExpirable
   */
  protected $keyValueExpirable;

  /**
   * The request service.
   *
   * @var \Symfony\Component\HttpFoundation\Request
   */
  protected $request;

  /**
   * @param KeyValueExpirableFactory $keyValueExpirable
   * @param RequestStack $request
   */
  public function __construct($keyValueExpirable, $request) {
    $this->keyValueExpirable = $keyValueExpirable;
    $this->request = $request->getCurrentRequest();
  }

  /**
   * Check if the ip address exists already in the KeyValueExpirable array.
   *
   * @param string $ip_address
   * @return bool|null
   */
  private function alreadyChecked(string $ip_address) {
    $result = $this->keyValueExpirable->get('abuse_ipdb')->getAll()[$ip_address];
    return $result;
  }

  /**
   * The result of the IP check will be stored to KeyValueExpirable.
   *
   * @param string $ip_address
   * @param bool $result
   */
  private function checkResult(string $ip_address, bool $result) {
    $this->keyValueExpirable->get('abuse_ipdb')->setWithExpire($ip_address, $result, 86400);
  }

  /**
   * Checks the IP address of the user against the AbuseIPDB database.
   *
   * @param $event
   * @return mixed
   * @throws \GuzzleHttp\Exception\GuzzleException
   */
  public function onRespond($event) {
    // To be moved to a file outside docroot.
    $api_key = 'YOUR_API_KEY';
    $ip_address = $this->request->getClientIp();

    $cached_result = $this->alreadyChecked($ip_address);

    if ($cached_result === true) {
      return $event;
    }

    if ($cached_result === false) {
      $exception = new Response('Access denied from your IP.', '403');
      $event->setResponse($exception);
      return $event;
    }

    $client = new Client([
      'base_uri' => 'https://api.abuseipdb.com/api/v2/'
    ]);

    $response = $client->request('GET', 'check', [
      'query' => [
        'ipAddress' => $ip_address,
      ],
      'headers' => [
        'Accept' => 'application/json',
        'Key' => $api_key,
      ],
    ]);

    $output = $response->getBody();

    $ipDetails = json_decode($output, true);

    // Default the result to true.
    $this->checkResult($ip_address, true);

    if (is_array($ipDetails) && $ipDetails['data']['abuseConfidenceScore'] > 50) {
      $this->checkResult($ip_address, false);
      $exception = new Response('Access denied from your IP.', '403');
      $event->setResponse($exception);
    }
    return $event;
  }


  /**
   * {@inheritdoc}
   */
  public static function getSubscribedEvents() {
    $events[KernelEvents::RESPONSE][] = ['onRespond'];
    return $events;
  }
}
