<?php
declare(strict_types=1);

namespace Bastion\Http\Controller;

use Bastion\Http\View;
use Bastion\IdentityAccess\Application\PasswordReset;
use Bastion\IdentityAccess\Domain\{NewPassword, ResetToken};
use Dzentota\Session\SessionManager;
use Psr\Http\Message\{ResponseInterface, ServerRequestInterface};

final class PasswordResetController
{
    private const SESSION_TOKEN = 'reset_token';

    public function __construct(private readonly PasswordReset $reset, private readonly View $view)
    {
    }

    public function form(ServerRequestInterface $request): ResponseInterface
    {
        return $this->view->admin($request, 'forgot', ['available' => $this->reset->isAvailable()]);
    }

    public function request(ServerRequestInterface $request): ResponseInterface
    {
        $ip = $request->getServerParams()['REMOTE_ADDR'] ?? '';
        $this->reset->request(Input::string($request, 'email', 320), is_string($ip) ? $ip : '');
        return $this->view->admin($request, 'forgot', ['available' => $this->reset->isAvailable(), 'sent' => true]);
    }

    /** Токен сразу переносится из URL в сессию: дальше он не светится в истории, логах и Referer. */
    public function arrive(ServerRequestInterface $request, SessionManager $session, ResetToken $token): ResponseInterface
    {
        if ($this->reset->accountFor($token) === null) {
            return $this->view->admin($request, 'reset', ['invalid' => true], 410);
        }
        $session->regenerateId();
        $session->set(self::SESSION_TOKEN, $token->toNative());
        return $this->view->redirect('/admin/reset');
    }

    public function choose(ServerRequestInterface $request, SessionManager $session): ResponseInterface
    {
        $account = $this->token($session) ? $this->reset->accountFor($this->token($session)) : null;
        return $account === null
            ? $this->view->admin($request, 'reset', ['invalid' => true], 410)
            : $this->view->admin($request, 'reset', ['username' => $account->username]);
    }

    public function complete(ServerRequestInterface $request, SessionManager $session): ResponseInterface
    {
        $token = $this->token($session);
        $account = $token ? $this->reset->accountFor($token) : null;
        if ($token === null || $account === null) {
            return $this->view->admin($request, 'reset', ['invalid' => true], 410);
        }
        $password = NewPassword::forUser(Input::string($request, 'password', 1024), $account->username, $result);
        if ($password === null) {
            return $this->view->admin($request, 'reset', ['username' => $account->username, 'error' => $result?->getFirstError()?->getMessage()], 422);
        }
        $ip = $request->getServerParams()['REMOTE_ADDR'] ?? '';
        $this->reset->complete($token, $password, is_string($ip) ? $ip : '');
        $session->destroy();
        return $this->view->redirect('/admin/login');
    }

    private function token(SessionManager $session): ?ResetToken
    {
        return ResetToken::tryParse($session->get(self::SESSION_TOKEN), $t) ? $t : null;
    }
}
