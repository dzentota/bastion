<?php
declare(strict_types=1);

namespace Bastion\Http\Controller;

use Bastion\Http\View;
use Bastion\IdentityAccess\Application\{LoginOutcome, TwoStepLogin};
use Dzentota\Session\SessionManager;
use Psr\Http\Message\{ResponseInterface, ServerRequestInterface};

final class AuthController
{
    public function __construct(private readonly TwoStepLogin $login, private readonly View $view)
    {
    }

    public function form(ServerRequestInterface $request): ResponseInterface
    {
        return $this->view->admin($request, 'login');
    }

    public function submit(ServerRequestInterface $request, SessionManager $session): ResponseInterface
    {
        $outcome = $this->login->password($request, $session, Input::string($request, 'username', 64), Input::string($request, 'password', 1024));
        return match ($outcome) {
            LoginOutcome::Authenticated => $this->view->redirect('/admin'),
            LoginOutcome::SecondFactorRequired => $this->view->redirect('/admin/2fa'),
            LoginOutcome::SecondFactorEnrollmentRequired => $this->view->redirect('/admin/2fa/setup'),
            LoginOutcome::Throttled => $this->view->admin($request, 'login', ['error' => 'Too many attempts. Try again later.'], 429),
            LoginOutcome::Rejected => $this->view->admin($request, 'login', ['error' => 'Invalid credentials or account temporarily locked.'], 401),
        };
    }

    public function totpForm(ServerRequestInterface $request, SessionManager $session): ResponseInterface
    {
        return $this->login->pendingAccount($session) ? $this->view->admin($request, 'totp') : $this->view->redirect('/admin/login');
    }

    public function totpSubmit(ServerRequestInterface $request, SessionManager $session): ResponseInterface
    {
        if ($this->login->totp($request, $session, Input::string($request, 'code', 6))) {
            return $this->view->redirect('/admin');
        }
        return $this->login->pendingAccount($session)
            ? $this->view->admin($request, 'totp', ['error' => 'Invalid code.'], 401)
            : $this->view->redirect('/admin/login');
    }

    public function enrollForm(ServerRequestInterface $request, SessionManager $session, ?string $error = null): ResponseInterface
    {
        $totp = $this->login->startEnrollment($session);
        if ($totp === null) {
            return $this->view->redirect('/admin/login');
        }
        return $this->view->admin($request, 'totp-setup', [
            'secret' => chunk_split($totp->getSecret(), 4, ' '),
            'uri' => $totp->getProvisioningUri(),
            'error' => $error,
        ], $error ? 401 : 200);
    }

    public function enrollSubmit(ServerRequestInterface $request, SessionManager $session): ResponseInterface
    {
        if ($this->login->confirmEnrollment($request, $session, Input::string($request, 'code', 6))) {
            return $this->view->redirect('/admin');
        }
        return $this->enrollForm($request, $session, 'Invalid code.');
    }

    public function logout(SessionManager $session): ResponseInterface
    {
        $this->login->logout($session);
        return $this->view->redirect('/admin/login');
    }
}
